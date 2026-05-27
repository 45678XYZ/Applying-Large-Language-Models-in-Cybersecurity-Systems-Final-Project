"""Layer 3 — LAN device discovery via python-nmap.

This is the core scanner: host discovery + top-N port scan + service/version
detection + OS fingerprinting + MAC address. Requires sudo for OS detection.
"""

from models import Device


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
    raise NotImplementedError
