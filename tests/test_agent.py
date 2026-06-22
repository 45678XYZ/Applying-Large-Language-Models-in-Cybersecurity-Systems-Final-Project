"""Agent-layer tests — tool selection & report assembly with stubbed LLM.

Covers the three modules B owns under `agent/`, all offline:
  * reporter — deterministic A–F grading + Markdown assembly (no LLM at all).
  * tools    — the SYNC-2 ``StructuredTool`` contract, with a stub retriever.
  * core     — the strictly-sequential scan pipeline + grounded Q&A, with the
               LLM, scanners, and retriever stubbed so nothing touches the
               network or Azure.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agent import core as agent_core
from agent import tools as agent_tools
from agent.core import SecurityAgent
from agent.reporter import assemble_report, grade_from_findings
from models import CVE, Device, NetworkInfo, Port, RiskFinding, RouterInfo, WiFiInfo


# ── shared builders ────────────────────────────────────────────────────────


def _finding(severity, dimension="iot_exposure", *, title=None, recommendation="Do the thing", cves=None):
    return RiskFinding(
        dimension=dimension,
        severity=severity,
        title=title or f"{severity} {dimension}",
        description="because reasons",
        recommendation=recommendation,
        related_cves=cves or [],
    )


def _network():
    return NetworkInfo(
        local_ip="192.168.1.50",
        subnet_cidr="192.168.1.0/24",
        gateway="192.168.1.1",
        dns_servers=["1.1.1.1"],
        interface="en0",
        is_wireless=True,
    )


def _wifi():
    return WiFiInfo(ssid="HomeNet", encryption="WPA2", band="5GHz")


def _router(gateway_ip="192.168.1.1"):
    return RouterInfo(gateway_ip=gateway_ip, model="TP-Link Archer AX73", admin_panel_exposed=True)


def _gateway_device():
    return Device(ip="192.168.1.1", vendor="TP-Link", ports=[Port(number=80, service="http")])


def _iot_device():
    return Device(
        ip="192.168.1.101",
        vendor="Hikvision",
        os_guess="Linux",
        ports=[Port(number=554, service="rtsp"), Port(number=80, service="http")],
    )


# ── reporter: deterministic grading + assembly (no LLM) ─────────────────────


def test_grade_rubric_covers_every_branch():
    assert grade_from_findings([]) == "A"
    assert grade_from_findings([_finding("info")]) == "A"  # info never lowers
    assert grade_from_findings([_finding("low")]) == "B"
    assert grade_from_findings([_finding("medium")]) == "B"
    assert grade_from_findings([_finding("medium")] * 3) == "B"  # below 4-medium cutoff
    assert grade_from_findings([_finding("medium")] * 4) == "C"
    assert grade_from_findings([_finding("high")]) == "C"
    # proposal anchor: 2 high + 3 medium + 1 low → C
    anchor = [_finding("high")] * 2 + [_finding("medium")] * 3 + [_finding("low")]
    assert grade_from_findings(anchor) == "C"
    assert grade_from_findings([_finding("high")] * 3) == "D"
    assert grade_from_findings([_finding("high")] * 4) == "D"
    assert grade_from_findings([_finding("high")] * 5) == "F"


def test_assemble_report_sorts_findings_and_renders_summary():
    findings = [_finding("low"), _finding("high", title="Open RTSP"), _finding("medium")]
    report = assemble_report(_network(), _wifi(), _router(), [_iot_device()], findings)

    # worst-first ordering
    assert [f.severity for f in report.findings] == ["high", "medium", "low"]
    assert report.overall_grade == "C"

    md = report.summary_markdown
    assert "# Home Network Security Audit Report" in md
    assert "Overall grade:** C" in md
    assert "## Findings" in md
    assert "## Risk Dimensions" in md
    assert "## Prioritised Remediation" in md
    assert "Open RTSP" in md


def test_assemble_report_clean_network_is_grade_a():
    report = assemble_report(_network(), None, None, [], [])
    assert report.overall_grade == "A"
    assert "No risks identified" in report.summary_markdown


def test_remediation_dedupes_and_orders_by_severity():
    findings = [
        _finding("low", recommendation="Patch firmware"),
        _finding("high", recommendation="Patch firmware"),  # same rec, higher severity
        _finding("medium", recommendation="Disable UPnP"),
    ]
    report = assemble_report(_network(), None, None, [], findings)
    section = report.summary_markdown.split("## Prioritised Remediation", 1)[1]

    assert section.count("Patch firmware") == 1  # deduped to one step
    assert section.index("Patch firmware") < section.index("Disable UPnP")  # high before medium


def test_findings_render_related_cves():
    cve = CVE(cve_id="CVE-2018-5371", cvss_score=7.5, description="d")
    report = assemble_report(_network(), None, _router(), [], [_finding("high", cves=[cve])])
    assert "CVE-2018-5371" in report.summary_markdown
    assert "CVSS 7.5" in report.summary_markdown


# ── tools: the SYNC-2 StructuredTool contract ──────────────────────────────

EXPECTED_TOOLS = [
    "get_network_info",
    "get_wifi_security",
    "scan_network",
    "check_router_info",
    "lookup_cve",
    "check_open_ports_risk",
]


class _StubRetriever:
    """Offline stand-in for ``rag.Retriever`` that records what it was asked."""

    def __init__(self):
        self.lookup_cve_calls: list[tuple[str, str | None]] = []
        self.search_calls: list[str] = []

    def lookup_cve(self, product, version=None, k=5, min_cvss=None):
        self.lookup_cve_calls.append((product, version))
        return [CVE(cve_id="CVE-2023-0001", cvss_score=8.1, description=f"stub CVE for {product}")]

    def lookup_port_risk(self, port, service=None, k=5):
        return [{"text": "t", "source": "owasp", "filename": "f.md", "distance": 0.1}]

    def search(self, query, k=5):
        self.search_calls.append(query)
        return [{"text": "WPA3 is stronger than WPA2.", "source": "nist", "filename": "n.pdf", "distance": 0.2}]


def test_build_tools_returns_expected_inventory():
    tools = agent_tools.build_tools(_StubRetriever())
    assert [t.name for t in tools] == EXPECTED_TOOLS
    assert all(t.args_schema is not None for t in tools)


def test_lookup_cve_tool_queries_retriever_and_returns_json():
    stub = _StubRetriever()
    tools = {t.name: t for t in agent_tools.build_tools(stub)}

    out = tools["lookup_cve"].invoke({"product": "TP-Link Archer", "min_cvss": 7.0})

    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert parsed[0]["cve_id"] == "CVE-2023-0001"
    assert stub.lookup_cve_calls == [("TP-Link Archer", None)]  # version defaulted to None


def test_scan_network_tool_serialises_devices(monkeypatch):
    monkeypatch.setattr(agent_tools, "scan_network", lambda *a, **k: [_iot_device()])
    tools = {t.name: t for t in agent_tools.build_tools(_StubRetriever())}

    out = tools["scan_network"].invoke({"subnet_cidr": "192.168.1.0/24", "do_os_detection": False})

    parsed = json.loads(out)
    assert parsed[0]["ip"] == "192.168.1.101"


# ── core: sequential pipeline + grounded Q&A, fully stubbed ─────────────────


class _FakeMessage:
    def __init__(self, content):
        self.content = content


class _FakeStructured:
    def __init__(self, findings):
        self._findings = findings

    def invoke(self, messages):
        return SimpleNamespace(findings=list(self._findings))


class _FakeLLM:
    """Stands in for a LangChain ``BaseChatModel`` — only the three methods
    ``SecurityAgent`` actually calls are implemented."""

    def __init__(self, synth=None, answer="Your network is graded C.", chunks=None):
        self._synth = synth or []
        self._answer = answer
        self._chunks = chunks if chunks is not None else ["Your ", "network ", "is C."]
        self.invoked = None
        self._structured = _FakeStructured(self._synth)

    def with_structured_output(self, schema):
        return self._structured

    def invoke(self, messages):
        self.invoked = messages
        return _FakeMessage(self._answer)

    def stream(self, messages):
        self.invoked = messages
        for chunk in self._chunks:
            yield _FakeMessage(chunk)


def _port_findings_for(device, retriever=None):
    if device.ip == "192.168.1.101":
        return [_finding("high", dimension="remote_attack_surface", title="Exposed RTSP", recommendation="Disable RTSP")]
    return []


def _patch_scanners(monkeypatch, *, scan=None, raise_scan=False):
    monkeypatch.setattr(agent_core, "get_network_info", lambda: _network())
    monkeypatch.setattr(agent_core, "get_wifi_security", lambda: _wifi())
    if raise_scan:
        def _boom(*a, **k):
            raise RuntimeError("nmap missing")
        monkeypatch.setattr(agent_core, "scan_network", _boom)
    else:
        devices = scan if scan is not None else [_gateway_device(), _iot_device()]
        monkeypatch.setattr(agent_core, "scan_network", lambda *a, **k: list(devices))
    monkeypatch.setattr(agent_core, "check_router_info", lambda gw: _router(gw))
    monkeypatch.setattr(agent_core, "check_open_ports_risk", _port_findings_for)


def _assert_in_order(events, needles):
    joined = "\n".join(events)
    last = -1
    for needle in needles:
        idx = joined.find(needle, last + 1)
        assert idx > last, f"event {needle!r} missing or out of order in {events}"
        last = idx


def test_run_full_scan_runs_pipeline_and_assembles_report(monkeypatch):
    _patch_scanners(monkeypatch)
    synth = [
        _finding(
            "high",
            dimension="router_vulnerability",
            title="Router CVE",
            recommendation="Update firmware",
            cves=[CVE(cve_id="CVE-2018-5371", cvss_score=7.5, description="d")],
        ),
        _finding("medium", dimension="wifi_encryption", title="WPA2 only", recommendation="Enable WPA3"),
    ]
    events: list[str] = []
    agent = SecurityAgent(_FakeLLM(synth=synth), _StubRetriever(), on_event=events.append)

    report = agent.run_full_scan()

    # 1 high (port) + 1 high + 1 medium (synth) → 2 high, 1 medium → grade C
    assert report.overall_grade == "C"
    assert agent.last_report is report

    # the gateway device gets flagged by IP match
    gateway = next(d for d in report.devices if d.ip == "192.168.1.1")
    assert gateway.is_gateway is True

    _assert_in_order(
        events,
        [
            "Reading local network configuration",
            "Checking Wi-Fi security",
            "Scanning 192.168.1.0/24",
            "Probing the router",
            "Looking up known CVEs",
            "Assessing open-port risks",
            "Synthesising findings",
            "Done — overall grade C.",
        ],
    )
    # CVE-backed synthesised finding flows through to the rendered report
    assert "CVE-2018-5371" in report.summary_markdown


def test_gather_cves_dedupes_repeated_products():
    stub = _StubRetriever()
    agent = SecurityAgent(_FakeLLM(), stub)
    devices = [
        Device(ip="192.168.1.10", vendor="Hikvision"),
        Device(ip="192.168.1.11", vendor="Hikvision"),  # same vendor → one query
    ]

    cves = agent._gather_cves(devices, None)

    assert stub.lookup_cve_calls == [("Hikvision", None)]
    assert set(cves) == {"192.168.1.10"}  # keyed by the first device that matched


def test_run_full_scan_degrades_when_a_scanner_fails(monkeypatch):
    _patch_scanners(monkeypatch, raise_scan=True)
    events: list[str] = []
    synth = [_finding("medium", dimension="wifi_encryption", recommendation="Enable WPA3")]
    agent = SecurityAgent(_FakeLLM(synth=synth), _StubRetriever(), on_event=events.append)

    report = agent.run_full_scan()

    assert report.devices == []  # the failed scan degraded to no devices
    assert report.overall_grade == "B"  # one medium from synthesis only
    assert any("device scan failed" in e for e in events)


def test_ask_returns_grounded_answer_using_report_and_kb(monkeypatch):
    _patch_scanners(monkeypatch)
    stub = _StubRetriever()
    llm = _FakeLLM(answer="Your Wi-Fi uses WPA2.")
    agent = SecurityAgent(llm, stub)
    agent.run_full_scan()

    answer = agent.ask("Is my Wi-Fi secure?")

    assert answer == "Your Wi-Fi uses WPA2."
    assert stub.search_calls == ["Is my Wi-Fi secure?"]
    human = llm.invoked[-1].content  # the grounded HumanMessage
    assert "Home Network Security Audit Report" in human
    assert "WPA3 is stronger than WPA2." in human
    assert "Is my Wi-Fi secure?" in human


def test_ask_stream_yields_answer_chunks(monkeypatch):
    _patch_scanners(monkeypatch)
    agent = SecurityAgent(_FakeLLM(chunks=["WPA2 ", "is okay."]), _StubRetriever())
    agent.run_full_scan()

    assert "".join(agent.ask_stream("How is my Wi-Fi?")) == "WPA2 is okay."


def test_qa_without_a_scan_returns_guidance():
    agent = SecurityAgent(_FakeLLM(), _StubRetriever())
    assert "No scan has been run yet" in agent.ask("anything")
    assert list(agent.ask_stream("anything")) == [SecurityAgent._NO_REPORT_MESSAGE]


def test_load_report_primes_qa_without_scanning():
    agent = SecurityAgent(_FakeLLM(answer="ok"), _StubRetriever())
    report = assemble_report(_network(), _wifi(), None, [], [])

    agent.load_report(report)

    assert agent.last_report is report
    assert agent.ask("hi") == "ok"
