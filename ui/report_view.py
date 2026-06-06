"""Visual rendering of a `ScanReport` inside Streamlit."""

from __future__ import annotations

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

    st.subheader("Security Report")
    grade_col, device_col, high_col, medium_col, generated_col = st.columns(
        [1, 1, 1, 1, 1.4]
    )
    grade_col.metric("Overall grade", report.overall_grade, GRADE_LABELS[report.overall_grade])
    device_col.metric("Devices", len(report.devices))
    high_col.metric("High", counts["high"])
    medium_col.metric("Medium", counts["medium"])
    generated_col.metric("Generated", generated)


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
    with st.container(border=True):
        st.markdown(f"**{finding.title}**")
        st.caption(
            f"{SEVERITY_LABELS[finding.severity]} | "
            f"{DIMENSION_LABEL.get(finding.dimension, finding.dimension)}"
            + (f" | {finding.affected}" if finding.affected else "")
        )
        st.write(finding.description)
        if finding.related_cves:
            cves = ", ".join(
                f"{cve.cve_id}"
                + (f" (CVSS {cve.cvss_score})" if cve.cvss_score is not None else "")
                for cve in finding.related_cves
            )
            st.write(f"Related CVEs: {cves}")
        st.write(f"Recommended action: {finding.recommendation}")


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
