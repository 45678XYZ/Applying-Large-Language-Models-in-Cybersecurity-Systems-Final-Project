"""Visual rendering of a `ScanReport` inside Streamlit."""

from __future__ import annotations

import html
from collections import Counter

import streamlit as st

from agent.reporter import DIMENSION_LABEL
from models import Device, RiskFinding, ScanReport

SEVERITY_ORDER = ("high", "medium", "low", "info")
SEVERITY_LABELS = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}
GRADE_LABELS = {
    "A": "Secure",
    "B": "Good",
    "C": "Needs improvement",
    "D": "At risk",
    "F": "Critical",
}


def render_report(report: ScanReport) -> None:
    """Render the overall grade, per-device table, and risk findings."""
    _render_header(report)
    _render_network_summary(report)
    _render_findings_summary(report.findings)
    _render_device_table(report.devices)
    _render_findings(report.findings)

    with st.expander("Markdown report", expanded=False):
        st.markdown(report.summary_markdown or "_No Markdown summary was generated._")


def _render_header(report: ScanReport) -> None:
    counts = _severity_counts(report.findings)
    generated = report.generated_at.strftime("%Y-%m-%d %H:%M")
    grade = report.overall_grade

    chips = [f'<span class="chip">{len(report.devices)} devices</span>']
    if counts["high"]:
        chips.append(f'<span class="chip chip-high">{counts["high"]} High</span>')
    if counts["medium"]:
        chips.append(f'<span class="chip chip-medium">{counts["medium"]} Medium</span>')
    chips.append(f'<span class="chip">Generated {generated}</span>')

    st.subheader("Security Report")
    st.markdown(
        f'<div class="grade-hero grade-{grade}">'
        f'<div class="grade-badge">{grade}</div>'
        f'<div><div class="grade-label">{GRADE_LABELS[grade]}</div>'
        f'<div class="grade-chips">{"".join(chips)}</div></div>'
        f"</div>",
        unsafe_allow_html=True,
    )


def _render_network_summary(report: ScanReport) -> None:
    net = report.network
    wifi = report.wifi
    router = report.router

    st.markdown("#### Network")
    left, middle, right = st.columns(3)
    left.write(f"**Local IP**  \n{net.local_ip}")
    left.write(f"**Subnet**  \n{net.subnet_cidr}")
    middle.write(f"**Gateway**  \n{net.gateway}")
    middle.write(f"**Interface**  \n{net.interface}")
    right.write(f"**DNS**  \n{', '.join(net.dns_servers) if net.dns_servers else 'Not detected'}")
    right.write(f"**Medium**  \n{'Wireless' if net.is_wireless else 'Wired'}")

    if wifi:
        st.caption(
            "Wi-Fi: "
            + " | ".join(
                part
                for part in (
                    wifi.ssid or "Hidden SSID",
                    wifi.encryption,
                    wifi.band if wifi.band != "UNKNOWN" else "",
                    f"{wifi.signal_dbm} dBm" if wifi.signal_dbm is not None else "",
                )
                if part
            )
        )
    if router:
        router_bits = [
            router.model or "unknown model",
            f"firmware {router.firmware_version}" if router.firmware_version else "",
            "admin panel exposed" if router.admin_panel_exposed else "",
            "UPnP enabled" if router.upnp_enabled else "",
        ]
        st.caption(
            f"Router {router.gateway_ip}: "
            + " | ".join(bit for bit in router_bits if bit)
        )


def _render_findings_summary(findings: list[RiskFinding]) -> None:
    st.markdown("#### Risk Dimensions")
    rows = []
    for dimension, label in DIMENSION_LABEL.items():
        tier = [finding for finding in findings if finding.dimension == dimension]
        if not tier:
            rows.append({"Dimension": label, "Worst severity": "None", "Findings": 0})
            continue
        worst = min(tier, key=lambda finding: SEVERITY_ORDER.index(finding.severity))
        rows.append(
            {
                "Dimension": label,
                "Worst severity": SEVERITY_LABELS[worst.severity],
                "Findings": len(tier),
            }
        )
    st.dataframe(rows, hide_index=True, width="stretch")


def _render_device_table(devices: list[Device]) -> None:
    st.markdown("#### Devices")
    if not devices:
        st.info("No devices were discovered.")
        return

    rows = []
    for device in devices:
        open_ports = [port for port in device.ports if port.state == "open"]
        rows.append(
            {
                "IP": device.ip,
                "Name": device.hostname or "",
                "Vendor": device.vendor or "",
                "Role": "Gateway" if device.is_gateway else "",
                "OS": device.os_guess or "",
                "Open ports": _format_ports(open_ports),
            }
        )
    st.dataframe(rows, hide_index=True, width="stretch")


def _render_findings(findings: list[RiskFinding]) -> None:
    st.markdown("#### Findings")
    if not findings:
        st.success("No risks were identified.")
        return

    tabs = st.tabs([SEVERITY_LABELS[severity] for severity in SEVERITY_ORDER])
    for tab, severity in zip(tabs, SEVERITY_ORDER, strict=True):
        tier = [finding for finding in findings if finding.severity == severity]
        with tab:
            if not tier:
                st.caption(f"No {severity} findings.")
                continue
            for finding in tier:
                _render_finding(finding)


def _render_finding(finding: RiskFinding) -> None:
    sev = finding.severity
    dimension = DIMENSION_LABEL.get(finding.dimension, finding.dimension)
    meta = dimension + (f" · {_esc(finding.affected)}" if finding.affected else "")

    cve_html = ""
    if finding.related_cves:
        cves = ", ".join(
            _esc(cve.cve_id)
            + (f" (CVSS {cve.cvss_score})" if cve.cvss_score is not None else "")
            for cve in finding.related_cves
        )
        cve_html = f'<div class="finding-cve">Related CVEs: {cves}</div>'

    st.markdown(
        f'<div class="finding-card sev-{sev}">'
        f'<div class="finding-head">'
        f'<span class="sev-pill sev-{sev}">{SEVERITY_LABELS[sev]}</span>'
        f'<span class="finding-dim">{meta}</span></div>'
        f'<div class="finding-title">{_esc(finding.title)}</div>'
        f'<div class="finding-desc">{_esc(finding.description)}</div>'
        f"{cve_html}"
        f'<div class="finding-rec"><b>Recommended action:</b> '
        f"{_esc(finding.recommendation)}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


def _esc(text: str) -> str:
    """HTML-escape dynamic (LLM/scan) text, keeping intentional line breaks."""
    return html.escape(text).replace("\n", "<br>")


def _severity_counts(findings: list[RiskFinding]) -> Counter[str]:
    counts = Counter(finding.severity for finding in findings)
    for severity in SEVERITY_ORDER:
        counts.setdefault(severity, 0)
    return counts


def _format_ports(open_ports: list) -> str:
    if not open_ports:
        return "None"
    shown = []
    for port in open_ports[:6]:
        label = f"{port.number}/{port.protocol}"
        if port.service:
            label += f" {port.service}"
        shown.append(label)
    extra = f" +{len(open_ports) - 6} more" if len(open_ports) > 6 else ""
    return ", ".join(shown) + extra
