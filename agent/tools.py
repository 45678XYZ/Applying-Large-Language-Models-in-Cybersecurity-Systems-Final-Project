"""LangChain Tool wrappers around the scanners + retriever.

`build_tools(retriever)` composes the six capabilities the agent plans around
into LangChain `StructuredTool`s, each with an explicit Pydantic argument
schema so the Tool-Calling Agent gets a typed signature to fill.

Design notes
------------
* **Return shape.** Every tool returns a JSON *string* — the standard
  observation shape for a tool-calling loop. `agent/core.py` (Phase 4) can
  upgrade to `response_format="content_and_artifact"` if it needs to recover
  the structured Pydantic objects without re-parsing; left out of this first
  draft to keep the SYNC 2 wiring minimal.
* **Retriever wiring.** Both `lookup_cve` and `check_open_ports_risk` use the
  one `retriever` passed in here: `lookup_cve` calls it directly, and the shared
  instance is injected into A's `scanners/port_risk.py` (its `retriever`
  parameter) so the whole agent reuses a single Chroma/embedder connection
  rather than letting port_risk build its own default.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from models import Device
from scanners import (
    check_open_ports_risk,
    check_router_info,
    get_network_info,
    get_wifi_security,
    scan_network,
)

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from rag import Retriever


# ── explicit argument schemas ─────────────────────────────────────────────


class _NoArgs(BaseModel):
    """Tool takes no arguments."""


class ScanNetworkArgs(BaseModel):
    subnet_cidr: str = Field(
        description="CIDR range to scan, e.g. '192.168.1.0/24' (from get_network_info)."
    )
    top_ports: int | None = Field(
        default=None,
        description="How many of nmap's top TCP ports to scan; omit to use the configured default.",
    )
    do_os_detection: bool = Field(
        default=True,
        description="Enable OS fingerprinting (-O). Needs sudo; falls back gracefully if unavailable.",
    )


class RouterInfoArgs(BaseModel):
    gateway_ip: str = Field(
        description="Gateway / router IP to probe (the 'gateway' field from get_network_info)."
    )


class LookupCveArgs(BaseModel):
    product: str = Field(
        description="Product or vendor to search, e.g. 'TP-Link Archer AX73' or 'Hikvision'."
    )
    version: str | None = Field(
        default=None, description="Firmware / software version, if known, to narrow the match."
    )
    min_cvss: float | None = Field(
        default=None, ge=0.0, le=10.0, description="Only return CVEs with a CVSS score at or above this."
    )
    k: int = Field(default=5, ge=1, le=20, description="Maximum number of CVEs to return.")


class CheckOpenPortsRiskArgs(BaseModel):
    device: Device = Field(
        description="A device returned by scan_network, including its discovered open ports."
    )


# ── factory ────────────────────────────────────────────────────────────────


def build_tools(retriever: "Retriever") -> list["BaseTool"]:
    """Compose every scanner / RAG capability into LangChain `BaseTool`s.

    Returned tools (names match the Agent's planned call sequence):
        - get_network_info
        - get_wifi_security
        - scan_network
        - check_router_info
        - lookup_cve
        - check_open_ports_risk
    """
    from langchain_core.tools import StructuredTool

    def _network_info() -> str:
        return get_network_info().model_dump_json()

    def _wifi_security() -> str:
        wifi = get_wifi_security()
        if wifi is None:
            return json.dumps(
                {"detected": False, "reason": "no wireless interface or Wi-Fi info unavailable"}
            )
        return wifi.model_dump_json()

    def _scan_network(
        subnet_cidr: str, top_ports: int | None = None, do_os_detection: bool = True
    ) -> str:
        devices = scan_network(subnet_cidr, top_ports=top_ports, do_os_detection=do_os_detection)
        return _dump_list(devices)

    def _router_info(gateway_ip: str) -> str:
        return check_router_info(gateway_ip).model_dump_json()

    def _lookup_cve(
        product: str, version: str | None = None, min_cvss: float | None = None, k: int = 5
    ) -> str:
        cves = retriever.lookup_cve(product, version=version, k=k, min_cvss=min_cvss)
        return _dump_list(cves)

    def _check_open_ports_risk(device: Device) -> str:
        # Share this agent's retriever so port_risk reuses one Chroma/embedder
        # connection instead of building its own per call.
        findings = check_open_ports_risk(device, retriever=retriever)
        return _dump_list(findings)

    return [
        StructuredTool.from_function(
            func=_network_info,
            name="get_network_info",
            description=(
                "Read the local host's network configuration: local IP, subnet CIDR, "
                "default gateway, DNS servers, and whether the link is wireless. Call this first."
            ),
            args_schema=_NoArgs,
        ),
        StructuredTool.from_function(
            func=_wifi_security,
            name="get_wifi_security",
            description=(
                "Inspect the current Wi-Fi connection: SSID, encryption (WPA3/WPA2/WPA/WEP/OPEN), "
                "band, and signal. Returns {'detected': false} on a wired or unsupported host."
            ),
            args_schema=_NoArgs,
        ),
        StructuredTool.from_function(
            func=_scan_network,
            name="scan_network",
            description=(
                "Discover live devices on a subnet and profile each one's open ports, service "
                "versions, OS guess, and vendor. The core LAN scan; can take a while on a /24."
            ),
            args_schema=ScanNetworkArgs,
        ),
        StructuredTool.from_function(
            func=_router_info,
            name="check_router_info",
            description=(
                "Probe the gateway/router: model and firmware hints, exposed admin panel, UPnP, "
                "and open Telnet/SSH. Use the gateway IP from get_network_info."
            ),
            args_schema=RouterInfoArgs,
        ),
        StructuredTool.from_function(
            func=_lookup_cve,
            name="lookup_cve",
            description=(
                "Retrieve known CVEs for a product/version from the vulnerability knowledge base. "
                "Only CVEs returned here may be cited — never invent CVE IDs."
            ),
            args_schema=LookupCveArgs,
        ),
        StructuredTool.from_function(
            func=_check_open_ports_risk,
            name="check_open_ports_risk",
            description=(
                "Assess the security risk of a device's open ports/services against the knowledge "
                "base, returning structured risk findings. Pass a device from scan_network."
            ),
            args_schema=CheckOpenPortsRiskArgs,
        ),
    ]


# ── helpers ────────────────────────────────────────────────────────────────


def _dump_list(objs: list[Any]) -> str:
    """Serialise a list of Pydantic models to a JSON-array string."""
    return json.dumps([obj.model_dump(mode="json") for obj in objs], ensure_ascii=False)
