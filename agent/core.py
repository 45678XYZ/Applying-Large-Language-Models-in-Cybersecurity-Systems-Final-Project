"""Sequential security-audit agent — top-level orchestrator.

Per the §7 decision (`docs/system-design.md`), orchestration is **strictly
sequential**: `run_full_scan` drives a fixed, code-defined scanner pipeline
(order is guaranteed here, not chosen by the LLM) and emits progress events so
the UI can stream them. The LLM is used only to (a) reason the non-port-level
risks into `RiskFinding`s and (b) answer Q&A. `reporter.assemble_report` then
computes the deterministic A–F grade and Markdown.

    run_full_scan():
        network → wifi → scan → router → lookup_cve(per device) →
        check_open_ports_risk(per device) → LLM synthesis → ScanReport
    ask(question):
        retriever.search + the last ScanReport → LLM answer
"""

from __future__ import annotations

import os
import warnings
from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel, Field

from config import settings
from config.prompts import (
    AGENT_SYSTEM_PROMPT,
    QA_FOLLOWUP_PROMPT,
    REPORT_GENERATION_PROMPT,
)
from models import CVE, Device, NetworkInfo, RiskFinding, RouterInfo, ScanReport, WiFiInfo
from rag import Retriever
from scanners import (
    check_open_ports_risk,
    check_router_info,
    get_network_info,
    get_wifi_security,
    scan_network,
)

from .reporter import assemble_report

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

ProgressCallback = Callable[[str], None]
_T = TypeVar("_T")


class _SynthesizedFindings(BaseModel):
    """Structured-output schema the LLM fills for non-port-level risks."""

    findings: list[RiskFinding] = Field(default_factory=list)


class SecurityAgent:
    """Sequential scan orchestrator + Q&A front end over the LLM and retriever."""

    def __init__(
        self,
        llm: "BaseChatModel",
        retriever: Retriever,
        on_event: ProgressCallback | None = None,
    ) -> None:
        """Wire the LLM, retriever, and an optional progress callback.

        `on_event` receives a short human-readable message per pipeline step;
        the UI renders these as streaming scan progress. Nothing runs until
        `run_full_scan` / `ask` is called.
        """
        self._llm = llm
        self._retriever = retriever
        self._on_event = on_event
        self._last_report: ScanReport | None = None

    @property
    def last_report(self) -> ScanReport | None:
        """The most recent ScanReport, or None before the first scan."""
        return self._last_report

    def load_report(self, report: ScanReport) -> None:
        """Prime Q&A from a previously produced report (e.g. an offline cache),
        without re-running a scan."""
        self._last_report = report

    # ── full scan ────────────────────────────────────────────────────────

    def run_full_scan(self) -> ScanReport:
        """Run the fixed scan pipeline and assemble a `ScanReport`.

        Each scanner step is isolated by `_safe`: if one fails (e.g. nmap is
        missing, a probe times out), it degrades to an empty/None result and the
        scan still assembles a report from whatever was collected, rather than
        crashing mid-demo. Reading the local network config is the one hard
        prerequisite — without it there is nothing to scan.
        """
        self._emit("Reading local network configuration…")
        network = get_network_info()

        self._emit("Checking Wi-Fi security…")
        wifi = self._safe("Wi-Fi check", get_wifi_security, None)

        # §7: OS fingerprinting (`nmap -O`) needs root, so it stays off by
        # default to keep the scan sudo-free. When the process *is* already
        # running as root, enable it automatically — root also lets nmap use
        # ARP host discovery, so this is exactly when OS data is available.
        do_os_detection = hasattr(os, "geteuid") and os.geteuid() == 0
        self._emit(
            f"Scanning {network.subnet_cidr} for devices…"
            + (" (with OS detection)" if do_os_detection else "")
        )
        devices = self._safe(
            "device scan",
            lambda: scan_network(
                network.subnet_cidr,
                top_ports=settings.nmap_top_ports,
                do_os_detection=do_os_detection,
            ),
            [],
        )
        self._emit(f"Found {len(devices)} device(s).")

        # The scanner can't know which host is the gateway (it never sees the
        # routing table), so flag it here — port_risk relies on `is_gateway` to
        # apply its gentler gateway-service baselines (e.g. UPnP = medium, not
        # high), and the report/UI mark the device as the gateway.
        for device in devices:
            if device.ip == network.gateway:
                device.is_gateway = True

        self._emit(f"Probing the router at {network.gateway}…")
        router = self._safe("router probe", lambda: check_router_info(network.gateway), None)

        self._emit("Looking up known CVEs…")
        cves = self._safe("CVE lookup", lambda: self._gather_cves(devices, router), {})

        self._emit("Assessing open-port risks…")
        port_findings: list[RiskFinding] = []
        for device in devices:
            port_findings.extend(
                self._safe(
                    f"port-risk check for {device.ip}",
                    lambda device=device: check_open_ports_risk(device, retriever=self._retriever),
                    [],
                )
            )

        self._emit("Synthesising findings…")
        findings = port_findings + self._synthesize_findings(
            network, wifi, router, devices, cves, port_findings
        )

        report = assemble_report(network, wifi, router, devices, findings)
        self._last_report = report
        self._emit(f"Done — overall grade {report.overall_grade}.")
        return report

    # ── Q&A ──────────────────────────────────────────────────────────────

    def ask(self, question: str) -> str:
        """Answer a follow-up question grounded in the last scan + KB."""
        if self._last_report is None:
            return (
                "No scan has been run yet. Start a scan first, then ask me about "
                "the results."
            )
        snippets = self._retriever.search(question, k=settings.rag_top_k)
        answer = self._llm.invoke(
            self._messages(QA_FOLLOWUP_PROMPT + self._qa_context(question, snippets))
        )
        return str(getattr(answer, "content", answer))

    # ── internals ────────────────────────────────────────────────────────

    def _emit(self, message: str) -> None:
        if self._on_event is not None:
            self._on_event(message)

    def _safe(self, label: str, fn: Callable[[], _T], default: _T) -> _T:
        """Run one scan step in isolation. On failure, emit an event and return
        `default` so a single broken scanner never sinks the whole scan."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - degrade, never crash the pipeline
            self._emit(f"⚠ {label} failed ({exc}); continuing with partial data.")
            return default

    def _gather_cves(self, devices: list[Device], router: RouterInfo | None) -> dict[str, list[CVE]]:
        """Look up CVEs per identifiable product: device vendors, the router
        model, and each open port's service product/version from `-sV`.

        The per-port products (e.g. "BusyBox http 1.19.4", "MiniUPnP 1.8") are
        what let the report cite real CVEs even when nmap could not resolve a
        MAC-based vendor — the common no-sudo case. Results are keyed by a
        device-aware label so the LLM can attribute each CVE to a host.
        """
        queries: list[tuple[str, str, str | None]] = []  # (label, product, version)
        seen: set[tuple[str, str | None]] = set()

        def add(label: str, product: str | None, version: str | None = None) -> None:
            product = (product or "").strip()
            if not product:
                return
            key = (product.lower(), (version or "").lower() or None)
            if key in seen:
                return
            seen.add(key)
            queries.append((label, product, version))

        for device in devices:
            add(device.ip, device.vendor)
            for port in device.ports:
                if port.state == "open" and port.product:
                    add(f"{device.ip} · {port.product}", port.product, port.version)
        if router and router.model:
            add(f"router {router.gateway_ip}", router.model)

        cves: dict[str, list[CVE]] = {}
        for label, product, version in queries:
            hits = self._retriever.lookup_cve(product, version=version, k=settings.rag_top_k)
            if hits:
                cves[label] = hits
        return cves

    def _synthesize_findings(
        self,
        network: NetworkInfo,
        wifi: WiFiInfo | None,
        router: RouterInfo | None,
        devices: list[Device],
        cves: dict[str, list[CVE]],
        port_findings: list[RiskFinding],
    ) -> list[RiskFinding]:
        """Ask the LLM for the non-port-level findings (Wi-Fi / router / isolation).

        Degrades gracefully: if the LLM call fails (e.g. an Azure latency spike
        mid-demo), the report still assembles from the deterministic port
        findings.
        """
        context = self._synthesis_context(network, wifi, router, devices, cves, port_findings)
        try:
            structured = self._llm.with_structured_output(_SynthesizedFindings)
            with warnings.catch_warnings():
                # with_structured_output emits a benign pydantic serializer
                # UserWarning for the wrapped schema; silence just that noise.
                warnings.simplefilter("ignore", UserWarning)
                result = structured.invoke(self._messages(REPORT_GENERATION_PROMPT + context))
            return list(result.findings)
        except Exception as exc:  # noqa: BLE001 - never let synthesis sink the scan
            self._emit(f"(LLM synthesis unavailable, using port findings only: {exc})")
            return []

    def _messages(self, human: str) -> list:
        from langchain_core.messages import HumanMessage, SystemMessage

        return [SystemMessage(content=AGENT_SYSTEM_PROMPT), HumanMessage(content=human)]

    # ── prompt-context formatting ─────────────────────────────────────────

    def _synthesis_context(
        self,
        network: NetworkInfo,
        wifi: WiFiInfo | None,
        router: RouterInfo | None,
        devices: list[Device],
        cves: dict[str, list[CVE]],
        port_findings: list[RiskFinding],
    ) -> str:
        already = "\n".join(f"- {f.dimension}: {f.title}" for f in port_findings) or "(none)"
        return (
            "\n\nGeneric open-port exposure has already been assessed and WILL be "
            "included in the report — do not repeat those. Produce findings for: "
            "wifi_encryption, network_isolation, and any remote_attack_surface risk "
            "not tied to a specific scanned port. ALSO, whenever the CVE context "
            "lists CVEs for a device/service, raise a CVE-backed finding that cites "
            "those specific CVE IDs (router_vulnerability for the gateway, or "
            "iot_exposure for another device) — even if a generic port-exposure "
            "finding already exists for that port.\n\n"
            f"== Network ==\n{network.model_dump_json()}\n\n"
            f"== Wi-Fi ==\n{wifi.model_dump_json() if wifi else 'not detected (wired or unavailable)'}\n\n"
            f"== Router ==\n{router.model_dump_json() if router else 'not probed'}\n\n"
            f"== Devices ==\n{self._format_devices(devices)}\n\n"
            f"== CVE context (cite IDs only from here) ==\n{self._format_cves(cves)}\n\n"
            f"== Open-port risks already captured (context only) ==\n{already}"
        )

    def _qa_context(self, question: str, snippets: list[dict]) -> str:
        report_md = self._last_report.summary_markdown if self._last_report else ""
        kb = "\n".join(
            f"- [{s.get('source', 'kb')}/{s.get('filename', '')}] {s.get('text', '')}"
            for s in snippets
        ) or "(no relevant snippets)"
        return (
            f"\n\n== Current scan report ==\n{report_md}\n\n"
            f"== Knowledge-base snippets ==\n{kb}\n\n"
            f"== Question ==\n{question}"
        )

    @staticmethod
    def _format_devices(devices: list[Device]) -> str:
        if not devices:
            return "(no devices discovered)"
        lines = []
        for d in devices:
            ports = ", ".join(
                f"{p.number}/{p.protocol} {p.service or ''}".strip()
                for p in d.ports
                if p.state == "open"
            )
            lines.append(
                f"- {d.ip} vendor={d.vendor or '?'} os={d.os_guess or '?'} "
                f"gateway={d.is_gateway} ports=[{ports or 'none'}]"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_cves(cves: dict[str, list[CVE]]) -> str:
        if not cves:
            return "(no CVEs found for any scanned product)"
        lines = []
        for product, items in cves.items():
            for cve in items:
                score = f" CVSS {cve.cvss_score}" if cve.cvss_score is not None else ""
                lines.append(f"- [{product}] {cve.cve_id}{score}: {cve.description[:160]}")
        return "\n".join(lines)
