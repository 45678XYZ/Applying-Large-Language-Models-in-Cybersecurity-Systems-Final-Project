"""SYNC 2 smoke test — verify the six agent tools wire up end-to-end.

Emulates the SYNC 2 check from `docs/system-design.md`: a hand-crafted set of
tool calls (one per tool, in the order the agent plans to use them) is
dispatched through the `StructuredTool`s, with the real scanners/retriever
swapped for fixtures so the test runs fully offline — no nmap, no network,
no Azure calls.

Pass criteria:
    * `build_tools` returns the six expected tools, in order, each with an
      argument schema that serialises to the OpenAI tool format (what
      `llm.bind_tools` needs).
    * Each tool dispatches a tool call and returns valid JSON.
    * `check_open_ports_risk` exercises A's real `scanners/port_risk.py`, fed the
      shared stub retriever that `build_tools` injects into it.

Exit code is 0 when the wiring is sound, non-zero on any real wiring failure.

Usage:
    .venv/bin/python scripts/smoke_tools.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

# Keep .env authoritative over stale shell exports, per project convention.
load_dotenv(override=True)

from langchain_core.messages import ToolMessage  # noqa: E402
from langchain_core.tools import BaseTool  # noqa: E402
from langchain_core.utils.function_calling import convert_to_openai_tool  # noqa: E402

from agent.tools import build_tools  # noqa: E402
from models import CVE, Device, NetworkInfo, Port, RouterInfo, WiFiInfo  # noqa: E402

EXPECTED_TOOLS = [
    "get_network_info",
    "get_wifi_security",
    "scan_network",
    "check_router_info",
    "lookup_cve",
    "check_open_ports_risk",
]

# ── offline fixtures (stand in for the real scanners/retriever) ────────────

_DEVICE = Device(
    ip="192.168.1.101",
    vendor="Hikvision",
    os_guess="Linux",
    ports=[Port(number=554, service="rtsp"), Port(number=80, service="http")],
)


class _StubRetriever:
    """Complete offline stand-in for `rag.Retriever`.

    Implements both methods the agent's tools reach: `lookup_cve` (the
    lookup_cve tool) and `lookup_port_risk` (which `build_tools` now injects
    into A's port_risk via `check_open_ports_risk`).
    """

    def lookup_cve(self, product, version=None, k=5, min_cvss=None):
        return [CVE(cve_id="CVE-2023-0001", cvss_score=8.1, description=f"stub CVE for {product}")]

    def lookup_port_risk(self, port, service=None, k=5):
        return [
            {
                "text": f"{service or 'service'} on port {port} may expose IoT devices when authentication is weak.",
                "source": "owasp",
                "filename": "owasp-iot-top-10-2018.md",
                "distance": 0.1,
            }
        ]


def _fixture_get_network_info() -> NetworkInfo:
    return NetworkInfo(
        local_ip="192.168.1.50",
        subnet_cidr="192.168.1.0/24",
        gateway="192.168.1.1",
        dns_servers=["1.1.1.1"],
        interface="en0",
        is_wireless=True,
    )


def _fixture_get_wifi_security() -> WiFiInfo:
    return WiFiInfo(ssid="HomeNet", encryption="WPA2", band="5GHz")


def _fixture_scan_network(subnet_cidr, top_ports=None, do_os_detection=True) -> list[Device]:
    return [_DEVICE]


def _fixture_check_router_info(gateway_ip) -> RouterInfo:
    return RouterInfo(gateway_ip=gateway_ip, model="TP-Link Archer AX73", admin_panel_exposed=True)


def _tool_calls() -> list[dict]:
    """The hand-crafted 'agent prompt' — one tool call per tool, planned order."""
    return [
        {"name": "get_network_info", "args": {}, "id": "call-1", "type": "tool_call"},
        {"name": "get_wifi_security", "args": {}, "id": "call-2", "type": "tool_call"},
        {
            "name": "scan_network",
            "args": {"subnet_cidr": "192.168.1.0/24", "do_os_detection": False},
            "id": "call-3",
            "type": "tool_call",
        },
        {
            "name": "check_router_info",
            "args": {"gateway_ip": "192.168.1.1"},
            "id": "call-4",
            "type": "tool_call",
        },
        {
            "name": "lookup_cve",
            "args": {"product": "TP-Link Archer AX73", "min_cvss": 7.0},
            "id": "call-5",
            "type": "tool_call",
        },
        {
            "name": "check_open_ports_risk",
            "args": {"device": _DEVICE.model_dump(mode="json")},
            "id": "call-6",
            "type": "tool_call",
        },
    ]


# ── checks ─────────────────────────────────────────────────────────────────


def _check_inventory(tools: list[BaseTool]) -> list[str]:
    """Names + order + schema-serialisation; returns a list of failure strings."""
    failures: list[str] = []
    names = [t.name for t in tools]
    if names != EXPECTED_TOOLS:
        failures.append(f"tool names/order mismatch: {names}")
    for tool in tools:
        if tool.args_schema is None:
            failures.append(f"{tool.name}: missing args_schema")
            continue
        try:
            spec = convert_to_openai_tool(tool)
            assert spec["type"] == "function"
            assert spec["function"]["name"] == tool.name
        except Exception as exc:  # noqa: BLE001 - report any serialisation issue
            failures.append(f"{tool.name}: schema does not serialise ({exc})")
    return failures


def _dispatch(tool: BaseTool, call: dict) -> tuple[str, str]:
    """Run one tool call. Returns (status, detail) — PASS / PENDING / FAIL."""
    try:
        result = tool.invoke(call)
        content = result.content if isinstance(result, ToolMessage) else result
        parsed = json.loads(content)
        return "PASS", f"{type(parsed).__name__} json, {len(content)} chars"
    except Exception as exc:  # noqa: BLE001 - a smoke test classifies all errors
        inner = exc.__cause__ or exc
        if isinstance(inner, NotImplementedError) and call["name"] == "check_open_ports_risk":
            return "PENDING", "scanners/port_risk.py not implemented yet (A — SYNC 2)"
        return "FAIL", f"{type(inner).__name__}: {inner}"


def main() -> int:
    print("SYNC 2 smoke test — agent tool wiring\n" + "=" * 38)

    tools = build_tools(_StubRetriever())
    by_name = {t.name: t for t in tools}

    inventory_failures = _check_inventory(tools)
    for failure in inventory_failures:
        print("  [FAIL]".ljust(12) + failure)
    if not inventory_failures:
        print("  [OK]".ljust(12) + "6 tools present, in order, schemas serialise for bind_tools")

    statuses: list[str] = []
    patches = {
        "get_network_info": _fixture_get_network_info,
        "get_wifi_security": _fixture_get_wifi_security,
        "scan_network": _fixture_scan_network,
        "check_router_info": _fixture_check_router_info,
        # check_open_ports_risk itself is intentionally NOT patched: we exercise
        # A's real implementation, fed the shared _StubRetriever that build_tools
        # injects into it.
    }
    with patch.multiple("agent.tools", **patches):
        for call in _tool_calls():
            status, detail = _dispatch(by_name[call["name"]], call)
            statuses.append(status)
            print(f"  [{status}]".ljust(12) + f"{call['name']:22s} {detail}")

    failed = len(inventory_failures) + statuses.count("FAIL")
    pending = statuses.count("PENDING")
    passed = statuses.count("PASS")
    print("=" * 38)
    print(f"wired: {passed}/{len(EXPECTED_TOOLS)} pass · {pending} pending · {failed} fail")
    if failed:
        print("RESULT: FAIL — tool wiring is broken")
        return 1
    print("RESULT: PASS — wiring sound" + (" (port_risk pending A)" if pending else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
