"""Phase 6 deterministic demo scenarios.

The live scanner is useful for the real demo, but final screenshots need stable
inputs. These three hand-authored networks cover the presentation path:

    clean_network      -> grade A, no findings
    risky_iot          -> grade C, IoT exposure without CVE claims
    vulnerable_router  -> grade D, router CVE and unsafe admin services

Usage:
    python scripts/demo_scenarios.py --list
    python scripts/demo_scenarios.py --export --out docs/demo-reports
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.reporter import assemble_report  # noqa: E402
from models import (  # noqa: E402
    CVE,
    Device,
    NetworkInfo,
    Port,
    RiskFinding,
    RouterInfo,
    ScanReport,
    WiFiInfo,
)


@dataclass(frozen=True)
class DemoScenario:
    """One deterministic scenario that can be rendered in the UI or exported."""

    scenario_id: str
    label: str
    summary: str
    expected_grade: str
    build: Callable[[], ScanReport]


def list_scenarios() -> list[DemoScenario]:
    """Return the Phase 6 demo scenarios in presentation order."""
    return [
        DemoScenario(
            "clean_network",
            "Clean network",
            "WPA3 home network, no risky services, grade A.",
            "A",
            _clean_network_report,
        ),
        DemoScenario(
            "risky_iot",
            "Risky IoT",
            "Camera and thermostat on the main subnet, grade C.",
            "C",
            _risky_iot_report,
        ),
        DemoScenario(
            "vulnerable_router",
            "Vulnerable router",
            "Outdated BusyBox gateway with Telnet and a cited CVE, grade D.",
            "D",
            _vulnerable_router_report,
        ),
    ]


def scenario_choices() -> dict[str, str]:
    """Map UI labels to stable scenario ids."""
    return {scenario.label: scenario.scenario_id for scenario in list_scenarios()}


def build_demo_report(scenario_id: str) -> ScanReport:
    """Assemble one deterministic `ScanReport` by scenario id."""
    for scenario in list_scenarios():
        if scenario.scenario_id == scenario_id:
            report = scenario.build()
            if report.overall_grade != scenario.expected_grade:
                raise AssertionError(
                    f"{scenario.scenario_id} expected grade {scenario.expected_grade}, "
                    f"got {report.overall_grade}"
                )
            return report
    available = ", ".join(s.scenario_id for s in list_scenarios())
    raise ValueError(f"unknown demo scenario {scenario_id!r}; choose one of: {available}")


def _clean_network_report() -> ScanReport:
    network = NetworkInfo(
        local_ip="192.168.10.25",
        subnet_cidr="192.168.10.0/24",
        gateway="192.168.10.1",
        dns_servers=["192.168.10.1", "1.1.1.1"],
        interface="en0",
        is_wireless=True,
    )
    wifi = WiFiInfo(ssid="Home-WPA3", encryption="WPA3", band="5GHz", signal_dbm=-45)
    router = RouterInfo(
        gateway_ip="192.168.10.1",
        model="Modern home gateway",
        firmware_version="2026.05",
        http_server_header="nginx",
        admin_panel_exposed=False,
        upnp_enabled=False,
        telnet_open=False,
        ssh_open=False,
    )
    devices = [
        Device(
            ip="192.168.10.1",
            hostname="gateway.local",
            vendor="ExampleNet",
            is_gateway=True,
            ports=[
                Port(number=53, service="domain"),
                Port(number=443, service="https", product="nginx"),
            ],
        ),
        Device(
            ip="192.168.10.31",
            hostname="workstation.local",
            vendor="Apple",
            os_guess="macOS",
            ports=[],
        ),
    ]
    return assemble_report(network, wifi, router, devices, [])


def _risky_iot_report() -> ScanReport:
    network = NetworkInfo(
        local_ip="192.168.20.44",
        subnet_cidr="192.168.20.0/24",
        gateway="192.168.20.1",
        dns_servers=["192.168.20.1"],
        interface="wlan0",
        is_wireless=True,
    )
    wifi = WiFiInfo(ssid="FamilyNet", encryption="WPA2", band="2.4GHz", signal_dbm=-61)
    router = RouterInfo(
        gateway_ip="192.168.20.1",
        model="ISP gateway",
        firmware_version="2025.10",
        admin_panel_exposed=False,
        upnp_enabled=False,
        telnet_open=False,
        ssh_open=False,
    )
    devices = [
        Device(
            ip="192.168.20.1",
            hostname="router.local",
            vendor="ISP",
            is_gateway=True,
            ports=[Port(number=53, service="domain"), Port(number=443, service="https")],
        ),
        Device(
            ip="192.168.20.23",
            hostname="frontdoor-cam.local",
            vendor="Hikvision",
            device_type="camera",
            ports=[Port(number=554, service="rtsp", product="Hikvision RTSP")],
        ),
        Device(
            ip="192.168.20.24",
            hostname="thermostat.local",
            vendor="Generic IoT",
            device_type="thermostat",
            ports=[Port(number=80, service="http", product="embedded httpd")],
        ),
        Device(
            ip="192.168.20.42",
            hostname="laptop.local",
            vendor="Lenovo",
            os_guess="Windows",
            ports=[],
        ),
    ]
    # NOTE: these four mediums put the grade at the `medium >= 4 -> C` threshold
    # (see reporter.grade_from_findings). Keep at least four medium findings, or
    # the grade silently drops to B and `build_demo_report`'s assertion fires.
    findings = [
        RiskFinding(
            dimension="wifi_encryption",
            severity="medium",
            title="Wi-Fi uses WPA2 rather than WPA3",
            description=(
                "FamilyNet negotiates WPA2. It is acceptable for compatibility, "
                "but weaker than WPA3 against offline password cracking."
            ),
            affected='SSID "FamilyNet"',
            recommendation="Enable WPA3 or WPA2/WPA3 mixed mode if all devices support it.",
        ),
        RiskFinding(
            dimension="iot_exposure",
            severity="medium",
            title="IP camera exposes RTSP on the main LAN",
            description=(
                "frontdoor-cam.local exposes RTSP on 554/tcp, a common target for "
                "default-password checks and stream scraping."
            ),
            affected="192.168.20.23 port 554/tcp",
            recommendation="Move cameras to an IoT VLAN or guest SSID and rotate their passwords.",
        ),
        RiskFinding(
            dimension="iot_exposure",
            severity="medium",
            title="Thermostat serves an unencrypted HTTP admin page",
            description=(
                "thermostat.local exposes HTTP on 80/tcp, so admin traffic can be "
                "observed by any host on the same LAN segment."
            ),
            affected="192.168.20.24 port 80/tcp",
            recommendation="Disable the local admin page or restrict it to a management VLAN.",
        ),
        RiskFinding(
            dimension="network_isolation",
            severity="medium",
            title="Personal devices and IoT devices share one subnet",
            description=(
                "The camera, thermostat, and laptop all sit on 192.168.20.0/24, "
                "so one compromised IoT device can directly reach the laptop."
            ),
            affected="192.168.20.0/24",
            recommendation="Create a guest or IoT SSID that cannot initiate connections to laptops.",
        ),
    ]
    return assemble_report(network, wifi, router, devices, findings)


def _vulnerable_router_report() -> ScanReport:
    network = NetworkInfo(
        local_ip="192.168.30.50",
        subnet_cidr="192.168.30.0/24",
        gateway="192.168.30.1",
        dns_servers=["192.168.30.1", "8.8.8.8"],
        interface="en0",
        is_wireless=True,
    )
    wifi = WiFiInfo(ssid="OldHome", encryption="WPA2", band="2.4GHz", signal_dbm=-70)
    router = RouterInfo(
        gateway_ip="192.168.30.1",
        model="BusyBox gateway",
        firmware_version="1.19.4",
        http_server_header="BusyBox httpd 1.19.4",
        admin_panel_exposed=True,
        upnp_enabled=True,
        telnet_open=True,
        ssh_open=False,
    )
    devices = [
        Device(
            ip="192.168.30.1",
            hostname="old-router.local",
            vendor="BusyBox",
            is_gateway=True,
            ports=[
                Port(number=23, service="telnet", product="BusyBox telnetd", version="1.19.4"),
                Port(number=80, service="http", product="BusyBox httpd", version="1.19.4"),
                Port(number=1900, protocol="udp", service="upnp", product="MiniUPnP", version="1.8"),
            ],
        ),
        Device(
            ip="192.168.30.18",
            hostname="nas.local",
            vendor="QNAP",
            device_type="NAS",
            ports=[Port(number=445, service="microsoft-ds", product="Samba")],
        ),
    ]
    busybox_cve = CVE(
        cve_id="CVE-2018-5371",
        cvss_score=8.8,
        cvss_severity="HIGH",
        description=(
            "BusyBox-based routers can mishandle crafted TCP packets, exposing "
            "older firmware to denial-of-service or worse."
        ),
    )
    findings = [
        RiskFinding(
            dimension="router_vulnerability",
            severity="high",
            title="Router firmware matches a high-severity BusyBox CVE",
            description=(
                "The gateway exposes BusyBox httpd 1.19.4, which matches a "
                "high-severity CVE returned by the knowledge base."
            ),
            affected="192.168.30.1 port 80/tcp",
            related_cves=[busybox_cve],
            recommendation="Upgrade or replace the router firmware before the demo network is reused.",
        ),
        RiskFinding(
            dimension="remote_attack_surface",
            severity="high",
            title="Telnet is open on the gateway",
            description=(
                "BusyBox telnetd is reachable on 23/tcp. Telnet sends credentials "
                "without encryption and is frequently targeted by automated attacks."
            ),
            affected="192.168.30.1 port 23/tcp",
            recommendation="Disable Telnet and use a hardened SSH or local-only admin path instead.",
        ),
        RiskFinding(
            dimension="remote_attack_surface",
            severity="high",
            title="UPnP can open WAN ports automatically",
            description=(
                "MiniUPnP 1.8 is reachable on UDP 1900, allowing LAN devices to "
                "request inbound port forwards without manual review."
            ),
            affected="192.168.30.1 port 1900/udp",
            recommendation="Disable UPnP unless a documented device needs it.",
        ),
        RiskFinding(
            dimension="wifi_encryption",
            severity="medium",
            title="Weak Wi-Fi posture on the router SSID",
            description="OldHome still uses WPA2 on a 2.4GHz-only SSID with a weak signal margin.",
            affected='SSID "OldHome"',
            recommendation="Move the SSID to WPA3 or WPA2/WPA3 mixed mode and review the passphrase.",
        ),
        RiskFinding(
            dimension="network_isolation",
            severity="medium",
            title="NAS shares the router subnet",
            description=(
                "The NAS sits on the same subnet as the vulnerable gateway, so a "
                "router compromise can immediately reach file-sharing services."
            ),
            affected="192.168.30.0/24",
            recommendation="Put storage devices behind a management VLAN or host firewall rules.",
        ),
    ]
    return assemble_report(network, wifi, router, devices, findings)


def _selected_scenarios(selection: str) -> list[DemoScenario]:
    scenarios = list_scenarios()
    if selection == "all":
        return scenarios
    return [scenario for scenario in scenarios if scenario.scenario_id == selection]


def _export(selection: str, out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    scenarios = _selected_scenarios(selection)
    if not scenarios:
        print(f"No scenario named {selection!r}", file=sys.stderr)
        return 1

    for scenario in scenarios:
        report = build_demo_report(scenario.scenario_id)
        json_path = out_dir / f"{scenario.scenario_id}.json"
        md_path = out_dir / f"{scenario.scenario_id}.md"
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        md_path.write_text(report.summary_markdown + "\n", encoding="utf-8")
        print(f"[OK] {scenario.scenario_id}: grade {report.overall_grade} -> {md_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Phase 6 demo reports.")
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["all", *(scenario.scenario_id for scenario in list_scenarios())],
        help="Scenario to export.",
    )
    parser.add_argument("--out", default="docs/demo-reports", type=Path)
    parser.add_argument("--list", action="store_true", help="List scenarios and exit.")
    parser.add_argument("--export", action="store_true", help="Export JSON and Markdown reports.")
    args = parser.parse_args()

    if args.list:
        for scenario in list_scenarios():
            print(
                f"{scenario.scenario_id:18} grade {scenario.expected_grade}  "
                f"{scenario.label}: {scenario.summary}"
            )
        return 0

    return _export(args.scenario, args.out)


if __name__ == "__main__":
    sys.exit(main())
