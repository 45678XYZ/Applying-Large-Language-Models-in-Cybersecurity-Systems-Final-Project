"""Layer 4 — gateway-specific HTTP probe and feature detection."""

from models import RouterInfo


def check_router_info(gateway_ip: str) -> RouterInfo:
    """Probe the gateway over HTTP/HTTPS and known feature ports.

    Extracts: vendor/model hints (Server header, HTML title), firmware
    fingerprints, admin-panel exposure, UPnP / Telnet / SSH presence.
    """
    raise NotImplementedError
