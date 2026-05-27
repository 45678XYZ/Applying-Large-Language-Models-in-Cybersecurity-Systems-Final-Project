"""Layer 1 — local host's network configuration (psutil + `ip route`)."""

from models import NetworkInfo


def get_network_info() -> NetworkInfo:
    """Detect local IP, subnet, default gateway, DNS servers, interface.

    No external network calls — purely introspects this host.
    """
    raise NotImplementedError
