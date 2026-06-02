"""Layer 3: LAN device discovery via python-nmap.

This is the core scanner: host discovery + top-N port scan + service/version
detection + OS fingerprinting + MAC address. Requires sudo for OS detection.
"""

from __future__ import annotations

import socket

from models import Device, Port
from utils.oui_lookup import lookup_vendor


def scan_network(
    subnet_cidr: str,
    top_ports: int | None = None,
    do_os_detection: bool = True,
) -> list[Device]:
    """Discover live hosts and profile their open ports / OS.

    Args:
        subnet_cidr: e.g. "192.168.1.0/24"; usually fed in from `NetworkInfo`.
        top_ports: How many of nmap's top TCP ports to scan; defaults to
            `settings.nmap_top_ports`.
        do_os_detection: Enable `-O` (requires sudo).
    """

    scanner = _new_port_scanner()
    arguments = _build_nmap_arguments(top_ports, do_os_detection)
    scanner.scan(hosts=subnet_cidr, arguments=arguments, timeout=_nmap_timeout_sec())

    devices: list[Device] = []
    for host in scanner.all_hosts():
        host_data = scanner[host]
        addresses = host_data.get("addresses", {})
        mac = addresses.get("mac")
        devices.append(
            Device(
                ip=addresses.get("ipv4") or host,
                mac=mac,
                hostname=_hostname_from_nmap(host_data, host),
                vendor=_vendor_from_nmap(host_data, mac),
                os_guess=_os_guess_from_nmap(host_data),
                ports=_ports_from_nmap(host_data),
            )
        )
    return devices


def _new_port_scanner():
    try:
        import nmap
    except ImportError as exc:  # pragma: no cover - environment dependent.
        raise RuntimeError("python-nmap is required for scan_network().") from exc
    return nmap.PortScanner()


def _build_nmap_arguments(top_ports: int | None, do_os_detection: bool) -> str:
    port_count = top_ports if top_ports is not None else _nmap_top_ports()
    port_count = max(1, int(port_count))
    parts = ["-sV", "--top-ports", str(port_count), "-T3"]
    if do_os_detection:
        parts.append("-O")
    return " ".join(parts)


def _nmap_top_ports() -> int:
    try:
        from config.settings import settings
    except ImportError:
        return 100
    return settings.nmap_top_ports


def _nmap_timeout_sec() -> int:
    try:
        from config.settings import settings
    except ImportError:
        return 300
    return settings.nmap_timeout_sec


def _hostname_from_nmap(host_data: dict, host: str) -> str | None:
    hostnames = host_data.get("hostnames") or []
    for item in hostnames:
        name = item.get("name") if isinstance(item, dict) else None
        if name:
            return name
    try:
        return socket.gethostbyaddr(host)[0]
    except (OSError, socket.herror):
        return None


def _vendor_from_nmap(host_data: dict, mac: str | None) -> str | None:
    if not mac:
        return None
    vendors = host_data.get("vendor") or {}
    return (
        vendors.get(mac)
        or vendors.get(mac.upper())
        or vendors.get(mac.lower())
        or lookup_vendor(mac)
    )


def _os_guess_from_nmap(host_data: dict) -> str | None:
    matches = host_data.get("osmatch") or []
    if not matches:
        return None

    best = matches[0]
    name = best.get("name")
    accuracy = best.get("accuracy")
    if name and accuracy:
        return f"{name} ({accuracy}% accuracy)"
    return name


def _ports_from_nmap(host_data: dict) -> list[Port]:
    ports: list[Port] = []
    for protocol in ("tcp", "udp"):
        protocol_data = host_data.get(protocol) or {}
        for number in sorted(protocol_data):
            raw = protocol_data[number] or {}
            ports.append(
                Port(
                    number=int(number),
                    protocol=protocol,
                    state=raw.get("state") or "open",
                    service=raw.get("name") or None,
                    product=raw.get("product") or None,
                    version=raw.get("version") or None,
                )
            )
    return ports
