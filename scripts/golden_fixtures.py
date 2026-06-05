"""Deterministic fixtures shared by the two regression scripts.

A live `nmap` scan is non-deterministic (devices come and go, services shift),
so it can't serve as a regression baseline. These hand-authored fixtures stand
in for one fixed home LAN whose graded output is stable run-to-run:

    golden_network()  → the (network, wifi, router, devices) snapshot
    golden_findings() → the fixed risk mix: 2 high + 3 medium + 1 low
    grade_scenarios() → boundary cases that pin every branch of the rubric

The finding mix lands on overall grade **C** — the same 2-high / 3-medium /
1-low severity mix the proposal's sample report (§4.2) uses as its grading
anchor. `golden_scan.py` checks the deterministic pipeline reproduces it;
`qa_regression.py` asks follow-up questions against it and checks the answers
stay grounded in exactly these facts.

⚠️ **Also load-bearing for the demo UI.** `ui/chat.py`'s "Load Demo Report"
button imports `golden_network` / `golden_findings` from here, so this module
is a shared contract now — not just a test helper. Keep those two functions'
return shapes stable, or update `ui/chat.py` in the same change.
"""

from __future__ import annotations

from models import (
    CVE,
    Device,
    NetworkInfo,
    Port,
    RiskFinding,
    RouterInfo,
    WiFiInfo,
)

# The CVE the high router finding cites. qa_regression checks the agent grounds
# its CVE answers in this exact id (taken live from the report) rather than
# inventing one, so it stays correct even when run against a different report.
GOLDEN_CVE_ID = "CVE-2018-5371"


def golden_network() -> tuple[NetworkInfo, WiFiInfo, RouterInfo, list[Device]]:
    """A fixed home LAN: a BusyBox gateway, a Wi-Fi IP camera, and a laptop."""
    network = NetworkInfo(
        local_ip="192.168.0.50",
        subnet_cidr="192.168.0.0/24",
        gateway="192.168.0.1",
        dns_servers=["192.168.0.1", "1.1.1.1"],
        interface="en0",
        is_wireless=True,
    )
    wifi = WiFiInfo(ssid="HomeNet", encryption="WPA2", band="5GHz", signal_dbm=-52)
    router = RouterInfo(
        gateway_ip="192.168.0.1",
        model="BusyBox gateway",
        firmware_version="1.19.4",
        http_server_header="BusyBox httpd 1.19.4",
        admin_panel_exposed=True,
        upnp_enabled=True,
        telnet_open=False,
        ssh_open=False,
    )
    devices = [
        Device(
            ip="192.168.0.1",
            vendor="BusyBox",
            is_gateway=True,
            ports=[
                Port(number=80, service="http", product="BusyBox http", version="1.19.4"),
                Port(number=1900, protocol="udp", service="upnp", product="MiniUPnP", version="1.8"),
            ],
        ),
        Device(
            ip="192.168.0.23",
            hostname="ipcam.local",
            vendor="Hangzhou Hikvision",
            os_guess="Linux 4.x",
            ports=[Port(number=554, service="rtsp", product="Hikvision RTSP")],
        ),
        Device(
            ip="192.168.0.42",
            hostname="laptop.local",
            vendor="Apple",
            os_guess="macOS",
            ports=[Port(number=22, service="ssh", product="OpenSSH", version="9.6")],
        ),
    ]
    return network, wifi, router, devices


def golden_findings() -> list[RiskFinding]:
    """The fixed finding mix — 2 high + 3 medium + 1 low → grade C.

    Deliberately spans all five risk dimensions and includes one CVE-backed
    high finding, so the report exercises every rendering branch.
    """
    busybox_cve = CVE(
        cve_id=GOLDEN_CVE_ID,
        cvss_score=8.8,
        cvss_severity="HIGH",
        description=(
            "net/ipv4/tcp_input.c in the Linux kernel as used in BusyBox-based "
            "routers mishandles certain TCP packets, allowing remote attackers "
            "to cause a denial of service or worse."
        ),
    )
    return [
        RiskFinding(
            dimension="router_vulnerability",
            severity="high",
            title="Router runs BusyBox httpd with a known high-severity CVE",
            description=(
                "The gateway at 192.168.0.1 exposes BusyBox httpd 1.19.4, which "
                "matches a known high-severity CVE in the knowledge base."
            ),
            affected="192.168.0.1 (gateway) port 80/tcp",
            related_cves=[busybox_cve],
            recommendation="Update the router firmware to the latest vendor release.",
        ),
        RiskFinding(
            dimension="remote_attack_surface",
            severity="high",
            title="UPnP is exposed on the gateway",
            description=(
                "MiniUPnP 1.8 is reachable on UDP 1900, letting LAN hosts open "
                "WAN ports automatically without the owner's knowledge."
            ),
            affected="192.168.0.1 (gateway) port 1900/udp",
            recommendation="Disable UPnP in the router admin panel unless a specific device needs it.",
        ),
        RiskFinding(
            dimension="wifi_encryption",
            severity="medium",
            title="Wi-Fi uses WPA2 rather than WPA3",
            description=(
                "The HomeNet SSID negotiates WPA2; WPA3 offers stronger "
                "protection against offline password cracking."
            ),
            affected='SSID "HomeNet"',
            recommendation="Switch the router to WPA3 (or WPA2/WPA3 mixed) if all devices support it.",
        ),
        RiskFinding(
            dimension="iot_exposure",
            severity="medium",
            title="IP camera exposes an RTSP stream",
            description=(
                "ipcam.local has RTSP (554/tcp) open — a common default-credential "
                "and stream-hijacking target for consumer cameras."
            ),
            affected="192.168.0.23 (ipcam.local) port 554/tcp",
            recommendation="Put the camera on a separate IoT VLAN and change its default password.",
        ),
        RiskFinding(
            dimension="network_isolation",
            severity="medium",
            title="No guest or IoT network separation detected",
            description=(
                "All devices share one subnet (192.168.0.0/24); a compromised IoT "
                "device can reach the laptop directly."
            ),
            affected="192.168.0.0/24",
            recommendation="Enable a guest/IoT SSID so untrusted devices are isolated from personal computers.",
        ),
        RiskFinding(
            dimension="remote_attack_surface",
            severity="low",
            title="SSH is open on the laptop",
            description=(
                "laptop.local has SSH (22/tcp) reachable on the LAN — fine if "
                "intended, but worth confirming it is needed."
            ),
            affected="192.168.0.42 (laptop.local) port 22/tcp",
            recommendation="Restrict SSH to known hosts or disable it if remote login is not needed.",
        ),
    ]


def grade_scenarios() -> list[tuple[str, list[RiskFinding], str]]:
    """`(name, findings, expected_grade)` cases that pin every rubric branch.

    Anchored to `reporter.grade_from_findings`:
        F = 5+ high · D = 3-4 high · C = 1-2 high or 4+ medium ·
        B = some medium/low, no high · A = nothing worse than info.
    """

    def mk(severity: str, n: int) -> list[RiskFinding]:
        return [
            RiskFinding(
                dimension="remote_attack_surface",
                severity=severity,  # type: ignore[arg-type]
                title=f"{severity} #{i}",
                description="fixture finding",
                recommendation="fixture recommendation",
            )
            for i in range(n)
        ]

    return [
        ("clean network", [], "A"),
        ("info only never lowers", mk("info", 3), "A"),
        ("single low", mk("low", 1), "B"),
        ("single medium", mk("medium", 1), "B"),
        ("three medium (below the 4-medium cutoff)", mk("medium", 3), "B"),
        ("four medium", mk("medium", 4), "C"),
        ("one high", mk("high", 1), "C"),
        ("proposal anchor: 2 high + 3 medium + 1 low", mk("high", 2) + mk("medium", 3) + mk("low", 1), "C"),
        ("three high", mk("high", 3), "D"),
        ("four high", mk("high", 4), "D"),
        ("five high", mk("high", 5), "F"),
    ]
