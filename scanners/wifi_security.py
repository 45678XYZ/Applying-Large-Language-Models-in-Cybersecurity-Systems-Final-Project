"""Layer 2 — Wi-Fi SSID, encryption, signal strength via nmcli/iwconfig."""

from models import WiFiInfo


def get_wifi_security() -> WiFiInfo | None:
    """Read currently-connected Wi-Fi's security posture.

    Returns None if the active interface is wired or no Wi-Fi info available.
    Linux: prefers `nmcli`. Falls back to `iwconfig` / `iw dev`.
    """
    raise NotImplementedError
