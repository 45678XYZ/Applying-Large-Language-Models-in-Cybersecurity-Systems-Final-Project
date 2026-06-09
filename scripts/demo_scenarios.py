"""Phase 6 deterministic demo scenarios.

The live scanner is useful for the real demo, but final screenshots need stable
inputs. These three hand-authored networks cover the presentation path:

    clean_network      -> grade A, no findings
    risky_iot          -> grade B, live-scan-style local LAN findings
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
from datetime import datetime
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
            "Live-scan-style local LAN with two devices, grade B.",
            "B",
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
        local_ip="172.20.10.2",
        subnet_cidr="172.20.10.0/28",
        gateway="172.20.10.1",
        dns_servers=["172.20.10.1"],
        interface="en0",
        is_wireless=True,
    )
    wifi = WiFiInfo(ssid="<redacted>", encryption="WPA3", band="2.4GHz", signal_dbm=-31)
    router = RouterInfo(
        gateway_ip="172.20.10.1",
        model=None,
        firmware_version=None,
        admin_panel_exposed=False,
        upnp_enabled=False,
        telnet_open=False,
        ssh_open=False,
    )
    devices = [
        Device(
            ip="172.20.10.1",
            hostname=None,
            vendor=None,
            os_guess="Apple iOS 15.0 - 16.1 (Darwin 21.1.0 - 22.1.0) (100% accuracy)",
            is_gateway=True,
            ports=[
                Port(number=21, service="ftp"),
                Port(number=53, service="domain"),
                Port(number=49152, service="tcpwrapped"),
            ],
        ),
        Device(
            ip="172.20.10.2",
            hostname=None,
            vendor=None,
            os_guess="Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0) (100% accuracy)",
            ports=[Port(number=5000, service="rtsp")],
        ),
    ]
    findings = [
        RiskFinding(
            dimension="wifi_encryption",
            severity="info",
            title="Wi-Fi uses WPA3",
            description="The active wireless network uses WPA3 with a strong signal.",
            affected='SSID "<redacted>"',
            recommendation="Keep WPA3 enabled and continue using a strong passphrase.",
        ),
        RiskFinding(
            dimension="iot_exposure",
            severity="medium",
            title="RTSP service is reachable on the local host",
            description=(
                "172.20.10.2 exposes RTSP on 5000/tcp. Media services should be "
                "limited to trusted clients and kept off shared networks when possible."
            ),
            affected="172.20.10.2 port 5000/tcp",
            recommendation="Restrict RTSP to trusted devices or disable it when it is not needed.",
        ),
        RiskFinding(
            dimension="network_isolation",
            severity="info",
            title="Small local subnet was scanned",
            description=(
                "The scan covered 172.20.10.0/28 and found only the gateway and local host."
            ),
            affected="172.20.10.0/28",
            recommendation="Keep untrusted IoT devices on a guest or IoT SSID when they are added.",
        ),
        RiskFinding(
            dimension="remote_attack_surface",
            severity="medium",
            title="Gateway exposes FTP",
            description=(
                "172.20.10.1 has FTP open on 21/tcp, which can expose credentials "
                "or files if enabled unintentionally."
            ),
            affected="172.20.10.1 port 21/tcp",
            recommendation="Disable FTP on the gateway unless it is required for a known management workflow.",
        ),
        RiskFinding(
            dimension="remote_attack_surface",
            severity="info",
            title="Gateway provides DNS locally",
            description="172.20.10.1 answers DNS on 53/tcp for the local network.",
            affected="172.20.10.1 port 53/tcp",
            recommendation="Leave DNS reachable only from the LAN and avoid exposing it to the internet.",
        ),
        RiskFinding(
            dimension="remote_attack_surface",
            severity="info",
            title="Gateway has a tcpwrapped high port",
            description=(
                "172.20.10.1 exposes 49152/tcp as tcpwrapped, which indicates "
                "access control is present but the service should be identified."
            ),
            affected="172.20.10.1 port 49152/tcp",
            recommendation=(
                "Confirm which gateway service owns 49152/tcp and disable it if it is unnecessary."
            ),
        ),
    ]
    report = assemble_report(network, wifi, router, devices, findings)
    report.generated_at = datetime(2026, 6, 9, 15, 59)
    report.summary_markdown = _risky_iot_summary_markdown()
    return report


def _risky_iot_summary_markdown() -> str:
    return """# Home Network Security Audit Report

**Generated:** 2026-06-09 15:59
**Overall grade:** B - Good
**Devices discovered:** 2 | High: 0 | Medium: 2 | Low: 0 | Info: 4

## Network Summary

- **Local host:** 172.20.10.2 (172.20.10.0/28) on en0 (wireless)
- **Gateway:** 172.20.10.1
- **DNS:** 172.20.10.1
- **Wi-Fi:** SSID "<redacted>" | WPA3 | 2.4GHz | -31 dBm
- **Router:** unknown model (at 172.20.10.1)

## Devices

- **172.20.10.1** [gateway] [Apple iOS 15.0 - 16.1 (Darwin 21.1.0 - 22.1.0) (100% accuracy)] | 3 open: 21/tcp ftp, 53/tcp domain, 49152/tcp tcpwrapped
- **172.20.10.2** [Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0) (100% accuracy)] | 1 open: 5000/tcp rtsp

## Findings

### Medium

1. **RTSP service is reachable on the local host** - 172.20.10.2 port 5000/tcp
   172.20.10.2 exposes RTSP on 5000/tcp. Media services should be limited to trusted clients and kept off shared networks when possible.
   *Recommendation:* Restrict RTSP to trusted devices or disable it when it is not needed.

2. **Gateway exposes FTP** - 172.20.10.1 port 21/tcp
   172.20.10.1 has FTP open on 21/tcp, which can expose credentials or files if enabled unintentionally.
   *Recommendation:* Disable FTP on the gateway unless it is required for a known management workflow.

### Info

1. **Wi-Fi uses WPA3** - SSID "<redacted>"
   The active wireless network uses WPA3 with a strong signal.
   *Recommendation:* Keep WPA3 enabled and continue using a strong passphrase.

2. **Small local subnet was scanned** - 172.20.10.0/28
   The scan covered 172.20.10.0/28 and found only the gateway and local host.
   *Recommendation:* Keep untrusted IoT devices on a guest or IoT SSID when they are added.

3. **Gateway provides DNS locally** - 172.20.10.1 port 53/tcp
   172.20.10.1 answers DNS on 53/tcp for the local network.
   *Recommendation:* Leave DNS reachable only from the LAN and avoid exposing it to the internet.

4. **Gateway has a tcpwrapped high port** - 172.20.10.1 port 49152/tcp
   172.20.10.1 exposes 49152/tcp as tcpwrapped, which indicates access control is present but the service should be identified.
   *Recommendation:* Confirm which gateway service owns 49152/tcp and disable it if it is unnecessary.

## Risk Dimensions

- **Router vulnerability:** no issues found
- **Wi-Fi encryption:** Info (1 finding)
- **IoT exposure:** Medium (1 finding)
- **Network isolation:** Info (1 finding)
- **Remote attack surface:** Medium (3 findings)

## Prioritised Remediation

1. Restrict RTSP to trusted devices or disable it when it is not needed.
2. Disable FTP on the gateway unless it is required for a known management workflow.
3. Confirm which gateway service owns 49152/tcp and disable it if it is unnecessary."""


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
