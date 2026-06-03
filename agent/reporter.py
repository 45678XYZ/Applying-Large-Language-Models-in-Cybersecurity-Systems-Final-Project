"""Convert intermediate tool outputs into the final `ScanReport`.

Pure assembly logic — no LLM calls. The Agent gives this module:
    - `NetworkInfo`, `WiFiInfo`, `RouterInfo`
    - `list[Device]`
    - `list[RiskFinding]` (already classified per dimension)
and gets back a `ScanReport` ready for the UI: overall A–F grade, findings
sorted by severity, and a deterministically rendered Markdown summary.

The grading rubric is anchored to the proposal's sample report (§4.2), where
2 high + 3 medium + 1 low findings yield an overall grade of **C**.
"""

from __future__ import annotations

from models import (
    CVE,
    Device,
    NetworkInfo,
    RiskDimension,
    RiskFinding,
    RouterInfo,
    ScanReport,
    Severity,
    WiFiInfo,
)

# ── presentation constants ────────────────────────────────────────────────

# Worst-first ordering used both for `ScanReport.findings` and the Markdown.
SEVERITY_ORDER: dict[Severity, int] = {"high": 0, "medium": 1, "low": 2, "info": 3}

SEVERITY_META: dict[Severity, tuple[str, str]] = {
    "high": ("🔴", "High"),
    "medium": ("🟡", "Medium"),
    "low": ("🟢", "Low"),
    "info": ("ℹ️", "Info"),
}

GRADE_LABEL: dict[str, str] = {
    "A": "Secure",
    "B": "Good",
    "C": "Needs improvement",
    "D": "At risk",
    "F": "Critical",
}

# Five risk dimensions in the proposal's presentation order (§3.2).
DIMENSION_LABEL: dict[RiskDimension, str] = {
    "router_vulnerability": "Router vulnerability",
    "wifi_encryption": "Wi-Fi encryption",
    "iot_exposure": "IoT exposure",
    "network_isolation": "Network isolation",
    "remote_attack_surface": "Remote attack surface",
}


# ── public API ────────────────────────────────────────────────────────────


def assemble_report(
    network: NetworkInfo,
    wifi: WiFiInfo | None,
    router: RouterInfo | None,
    devices: list[Device],
    findings: list[RiskFinding],
) -> ScanReport:
    """Compute the overall grade, sort findings by severity, render summary."""
    ordered = _sort_findings(findings)
    report = ScanReport(
        network=network,
        wifi=wifi,
        router=router,
        devices=list(devices),
        findings=ordered,
        overall_grade=grade_from_findings(ordered),
    )
    # Render from the assembled object so the timestamp in the summary matches
    # `report.generated_at` exactly.
    report.summary_markdown = _render_summary(report)
    return report


def grade_from_findings(findings: list[RiskFinding]) -> str:
    """A–F grade from the count/severity mix of findings.

    Cascade (first match wins), anchored to the proposal sample report:
        F  — 5+ high
        D  — 3–4 high
        C  — 1–2 high, or 4+ medium
        B  — at least one medium or low, but no high
        A  — nothing worse than informational

    `info` findings never lower the grade; `low` findings keep a clean
    network at B rather than A.
    """
    counts = _severity_counts(findings)
    high, medium, low = counts["high"], counts["medium"], counts["low"]

    if high >= 5:
        return "F"
    if high >= 3:
        return "D"
    if high >= 1 or medium >= 4:
        return "C"
    if medium >= 1 or low >= 1:
        return "B"
    return "A"


# ── findings helpers ──────────────────────────────────────────────────────


def _sort_findings(findings: list[RiskFinding]) -> list[RiskFinding]:
    """Stable sort, most severe first; preserves input order within a tier."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


def _severity_counts(findings: list[RiskFinding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


# ── Markdown rendering ────────────────────────────────────────────────────


def _render_summary(report: ScanReport) -> str:
    """Assemble a human-readable Markdown report from structured data only."""
    sections = [
        _render_header(report),
        _render_network_summary(report),
        _render_device_inventory(report.devices),
        _render_findings(report.findings),
        _render_dimension_breakdown(report.findings),
        _render_remediation(report.findings),
    ]
    return "\n\n".join(section for section in sections if section)


def _render_header(report: ScanReport) -> str:
    grade = report.overall_grade
    counts = _severity_counts(report.findings)
    when = report.generated_at.strftime("%Y-%m-%d %H:%M")
    return (
        "# Home Network Security Audit Report\n\n"
        f"**Generated:** {when}  \n"
        f"**Overall grade:** {grade} — {GRADE_LABEL.get(grade, '')}  \n"
        f"**Devices discovered:** {len(report.devices)} | "
        f"High: {counts['high']} · Medium: {counts['medium']} · "
        f"Low: {counts['low']}"
    )


def _render_network_summary(report: ScanReport) -> str:
    net = report.network
    lines = ["## Network Summary", ""]
    medium = "wireless" if net.is_wireless else "wired"
    lines.append(f"- **Local host:** {net.local_ip} ({net.subnet_cidr}) on {net.interface} ({medium})")
    lines.append(f"- **Gateway:** {net.gateway}")
    if net.dns_servers:
        lines.append(f"- **DNS:** {', '.join(net.dns_servers)}")
    lines.append(_wifi_line(report.wifi))
    lines.append(_router_line(report.router))
    return "\n".join(lines)


def _wifi_line(wifi: WiFiInfo | None) -> str:
    if wifi is None:
        return "- **Wi-Fi:** not detected (wired or unavailable)"
    parts = [f'SSID "{wifi.ssid}"' if wifi.ssid else "SSID hidden", wifi.encryption]
    if wifi.band != "UNKNOWN":
        parts.append(wifi.band)
    return f"- **Wi-Fi:** {' · '.join(parts)}"


def _router_line(router: RouterInfo | None) -> str:
    if router is None:
        return "- **Router:** not probed"
    parts: list[str] = [router.model or "unknown model"]
    if router.firmware_version:
        parts.append(f"firmware {router.firmware_version}")
    if router.admin_panel_exposed:
        parts.append("admin panel exposed")
    return f"- **Router:** {' · '.join(parts)} (at {router.gateway_ip})"


def _render_device_inventory(devices: list[Device]) -> str:
    if not devices:
        return "## Devices\n\nNo devices discovered."
    lines = ["## Devices", ""]
    for device in devices:
        label = device.hostname or device.vendor or "unknown device"
        tags = []
        if device.is_gateway:
            tags.append("gateway")
        if device.os_guess:
            tags.append(device.os_guess)
        suffix = f" [{', '.join(tags)}]" if tags else ""
        ports = _format_ports(device)
        lines.append(f"- **{device.ip}** — {label}{suffix} · {ports}")
    return "\n".join(lines)


def _format_ports(device: Device) -> str:
    open_ports = [p for p in device.ports if p.state == "open"]
    if not open_ports:
        return "no open ports"
    shown = ", ".join(
        f"{p.number}/{p.protocol}" + (f" {p.service}" if p.service else "")
        for p in open_ports[:6]
    )
    extra = f" (+{len(open_ports) - 6} more)" if len(open_ports) > 6 else ""
    return f"{len(open_ports)} open: {shown}{extra}"


def _render_findings(findings: list[RiskFinding]) -> str:
    if not findings:
        return "## Findings\n\nNo risks identified — the network looks clean."
    blocks = ["## Findings"]
    for severity in ("high", "medium", "low", "info"):
        tier = [f for f in findings if f.severity == severity]
        if not tier:
            continue
        emoji, label = SEVERITY_META[severity]
        blocks.append(f"### {emoji} {label}")
        blocks.extend(_render_finding(i, f) for i, f in enumerate(tier, 1))
    return "\n\n".join(blocks)


def _render_finding(index: int, finding: RiskFinding) -> str:
    lines = [f"{index}. **{finding.title}**"]
    if finding.affected:
        lines[0] += f" — {finding.affected}"
    lines.append(f"   {finding.description}")
    if finding.related_cves:
        lines.append(f"   *Related CVEs:* {_format_cves(finding.related_cves)}")
    lines.append(f"   *Recommendation:* {finding.recommendation}")
    return "\n".join(lines)


def _format_cves(cves: list[CVE]) -> str:
    rendered = []
    for cve in cves:
        score = f" (CVSS {cve.cvss_score})" if cve.cvss_score is not None else ""
        rendered.append(f"{cve.cve_id}{score}")
    return ", ".join(rendered)


def _render_dimension_breakdown(findings: list[RiskFinding]) -> str:
    lines = ["## Risk Dimensions", ""]
    for dimension, label in DIMENSION_LABEL.items():
        tier = [f for f in findings if f.dimension == dimension]
        if not tier:
            lines.append(f"- **{label}:** ✅ no issues found")
            continue
        worst = min(tier, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        emoji, sev_label = SEVERITY_META[worst.severity]
        count = f"{len(tier)} finding" + ("s" if len(tier) > 1 else "")
        lines.append(f"- **{label}:** {emoji} {sev_label} ({count})")
    return "\n".join(lines)


def _render_remediation(findings: list[RiskFinding]) -> str:
    if not findings:
        return ""
    lines = ["## Prioritised Remediation", ""]
    seen: set[str] = set()
    step = 1
    for finding in findings:  # already severity-sorted
        rec = finding.recommendation.strip()
        if not rec or rec in seen:
            continue
        seen.add(rec)
        emoji, _ = SEVERITY_META[finding.severity]
        lines.append(f"{step}. {emoji} {rec}")
        step += 1
    return "\n".join(lines)
