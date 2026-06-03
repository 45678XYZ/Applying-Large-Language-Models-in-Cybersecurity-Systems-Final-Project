"""Scanner-layer tests: fixture-driven, no real network calls."""

from __future__ import annotations

import socket
from pathlib import Path

from models import Device, Port
from scanners import nmap_scanner, port_risk, router_probe, wifi_security
from utils import oui_lookup


def test_oui_lookup_normalises_common_mac_formats(tmp_path, monkeypatch):
    oui_file = tmp_path / "oui.csv"
    oui_file.write_text("prefix,vendor\nAABBCC,Example Networks\n", encoding="utf-8")

    monkeypatch.setattr(oui_lookup, "OUI_DATA_PATH", Path(oui_file))
    oui_lookup._load_oui_table.cache_clear()

    assert oui_lookup.lookup_vendor("aa:bb:cc:11:22:33") == "Example Networks"
    assert oui_lookup.lookup_vendor("aabb.cc11.2233") == "Example Networks"
    assert oui_lookup.lookup_vendor("00:11") is None

    oui_lookup._load_oui_table.cache_clear()


def test_wifi_security_parses_active_nmcli_row():
    output = "no:Other:WPA2:40:2412\nyes:Home\\:Lab:WPA3:82:5955\n"

    info = wifi_security._parse_nmcli(output)

    assert info is not None
    assert info.ssid == "Home:Lab"
    assert info.encryption == "WPA3"
    assert info.signal_dbm == -59
    assert info.band == "6GHz"
    assert info.model_dump_json()


def test_wifi_security_parses_windows_netsh(monkeypatch):
    monkeypatch.setattr(wifi_security.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        wifi_security,
        "_run_text",
        lambda args: """
            Name                   : Wi-Fi
            State                  : connected
            SSID                   : HomeLab
            BSSID                  : aa:bb:cc:dd:ee:ff
            Authentication         : WPA2-Personal
            Signal                 : 76%
            Channel                : 11
        """,
    )

    info = wifi_security.get_wifi_security()

    assert info is not None
    assert info.ssid == "HomeLab"
    assert info.encryption == "WPA2"
    assert info.signal_dbm == -62
    assert info.band == "2.4GHz"


def test_router_probe_aggregates_http_and_ports(monkeypatch):
    def fake_http_probe(gateway_ip: str, scheme: str):
        if scheme == "https":
            return None
        return router_probe.HttpProbeResult(
            url=f"http://{gateway_ip}/",
            status_code=200,
            server_header="TP-Link Router Web Server",
            title="TP-Link Archer AX73 Login",
            body_excerpt="Firmware Version: 1.2.3 Build 20260101 password",
        )

    monkeypatch.setattr(router_probe, "_http_probe", fake_http_probe)
    monkeypatch.setattr(router_probe, "_probe_upnp", lambda gateway_ip: True)
    monkeypatch.setattr(router_probe, "_is_tcp_open", lambda host, port: port == 22)

    info = router_probe.check_router_info("192.168.1.1")

    assert info.gateway_ip == "192.168.1.1"
    assert info.model == "TP-Link Archer AX73"
    assert info.firmware_version == "1.2.3"
    assert info.http_server_header == "TP-Link Router Web Server"
    assert info.admin_panel_exposed is True
    assert info.upnp_enabled is True
    assert info.telnet_open is False
    assert info.ssh_open is True
    assert info.model_dump_json()


def test_nmap_scanner_maps_fixture_to_devices(monkeypatch):
    class FakeScanner:
        def __init__(self):
            self.hosts = {
                "192.168.1.10": {
                    "addresses": {"ipv4": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"},
                    "vendor": {"AA:BB:CC:DD:EE:FF": "Example Networks"},
                    "hostnames": [{"name": "camera.local"}],
                    "osmatch": [{"name": "Linux 5.x", "accuracy": "94"}],
                    "tcp": {
                        22: {
                            "state": "open",
                            "name": "ssh",
                            "product": "OpenSSH",
                            "version": "9.6",
                        },
                        80: {"state": "open", "name": "http", "product": "nginx"},
                    },
                }
            }
            self.last_scan = None

        def scan(self, hosts, arguments, timeout):
            self.last_scan = (hosts, arguments, timeout)

        def all_hosts(self):
            return list(self.hosts)

        def __getitem__(self, host):
            return self.hosts[host]

    fake = FakeScanner()
    monkeypatch.setattr(nmap_scanner, "_new_port_scanner", lambda: fake)

    devices = nmap_scanner.scan_network("192.168.1.0/24", top_ports=25, do_os_detection=True)

    assert fake.last_scan[0] == "192.168.1.0/24"
    assert "--top-ports 25" in fake.last_scan[1]
    assert "-sV" in fake.last_scan[1]
    assert "-O" in fake.last_scan[1]
    assert len(devices) == 1
    assert devices[0].hostname == "camera.local"
    assert devices[0].vendor == "Example Networks"
    assert devices[0].os_guess == "Linux 5.x (94% accuracy)"
    assert [port.number for port in devices[0].ports] == [22, 80]
    assert devices[0].model_dump_json()


def test_nmap_scanner_uses_oui_vendor_fallback(monkeypatch, tmp_path):
    oui_file = tmp_path / "oui.csv"
    oui_file.write_text("prefix,vendor\nAABBCC,OUI Fallback Vendor\n", encoding="utf-8")
    oui_lookup._load_oui_table.cache_clear()
    monkeypatch.setattr(oui_lookup, "OUI_DATA_PATH", Path(oui_file))

    class FakeScanner:
        def __init__(self):
            self.hosts = {
                "192.168.1.11": {
                    "addresses": {"ipv4": "192.168.1.11", "mac": "AA:BB:CC:11:22:33"},
                    "vendor": {},
                    "hostnames": [],
                }
            }

        def scan(self, hosts, arguments, timeout):
            pass

        def all_hosts(self):
            return list(self.hosts)

        def __getitem__(self, host):
            return self.hosts[host]

    monkeypatch.setattr(nmap_scanner, "_new_port_scanner", FakeScanner)
    monkeypatch.setattr(nmap_scanner.socket, "gethostbyaddr", lambda host: (_ for _ in ()).throw(socket.herror()))

    devices = nmap_scanner.scan_network("192.168.1.0/24", top_ports=10, do_os_detection=False)

    assert devices[0].vendor == "OUI Fallback Vendor"

    oui_lookup._load_oui_table.cache_clear()


def test_port_risk_calls_retriever_for_each_open_port():
    class FakeRetriever:
        def __init__(self):
            self.calls = []

        def lookup_port_risk(self, port, service=None, k=5):
            self.calls.append((port, service, k))
            return [
                {
                    "text": "RTSP camera services may expose video streams and default password risks.",
                    "source": "owasp",
                    "filename": "owasp-iot-top-10-2018.md",
                    "distance": 0.12,
                }
            ]

    retriever = FakeRetriever()
    device = Device(
        ip="192.168.1.101",
        hostname="camera.local",
        vendor="Hikvision",
        ports=[
            Port(number=554, service="rtsp", product="Hikvision RTSP"),
            Port(number=80, service="http", state="closed"),
        ],
    )

    findings = port_risk.check_open_ports_risk(device, retriever=retriever, k=3)

    assert retriever.calls == [(554, "rtsp", 3)]
    assert len(findings) == 1
    assert findings[0].dimension == "iot_exposure"
    assert findings[0].severity == "high"
    assert findings[0].affected == "camera.local / Hikvision port 554/tcp"
    assert "owasp-iot-top-10-2018.md" in findings[0].description
    assert findings[0].model_dump_json()


def test_port_risk_returns_empty_for_device_without_open_ports():
    class ShouldNotBeCalled:
        def lookup_port_risk(self, port, service=None, k=5):
            raise AssertionError("retriever should not be called")

    device = Device(ip="192.168.1.50", ports=[Port(number=22, service="ssh", state="closed")])

    assert port_risk.check_open_ports_risk(device, retriever=ShouldNotBeCalled()) == []
