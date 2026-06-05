"""Layer 2: Wi-Fi SSID, encryption, signal strength via native tools."""

from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path

from models import WiFiInfo

_AIRPORT = (
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/"
    "Current/Resources/airport"
)


def get_wifi_security() -> WiFiInfo | None:
    """Read the currently-connected Wi-Fi's security posture.

    Returns ``None`` when the active interface is wired or no Wi-Fi state is
    available. Linux prefers ``nmcli`` and falls back to ``iwconfig``; macOS
    uses ``airport`` / ``networksetup``; Windows uses ``netsh`` as a graceful
    local-development fallback.
    """

    system = platform.system().lower()
    if system == "linux":
        return _linux_wifi_security()
    if system == "darwin":
        return _darwin_wifi_security()
    if system == "windows":
        return _windows_wifi_security()
    return None


def _linux_wifi_security() -> WiFiInfo | None:
    info = _parse_nmcli(
        _run_text(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY,SIGNAL,FREQ", "dev", "wifi", "list"])
    )
    if info:
        return info
    return _parse_iwconfig(_run_text(["iwconfig"]))


def _parse_nmcli(output: str) -> WiFiInfo | None:
    for line in output.splitlines():
        fields = _split_nmcli_line(line)
        if len(fields) < 5 or fields[0].lower() not in {"yes", "*"}:
            continue

        ssid, security, signal, freq = fields[1], fields[2], fields[3], fields[4]
        return WiFiInfo(
            ssid=ssid or None,
            encryption=_normalise_encryption(security),
            signal_dbm=_signal_percent_to_dbm(signal),
            band=_band_from_frequency(freq),
            hidden=not bool(ssid),
        )
    return None


def _split_nmcli_line(line: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def _parse_iwconfig(output: str) -> WiFiInfo | None:
    if not output or "ESSID" not in output:
        return None

    match = re.search(r'ESSID:"(?P<ssid>[^"]*)"', output)
    ssid = match.group("ssid") if match else ""
    if not ssid or ssid.lower() in {"off/any", "any"}:
        return None

    signal_match = re.search(r"Signal level[=:](?P<signal>-?\d+)", output)
    frequency_match = re.search(r"Frequency:(?P<freq>[0-9.]+)\s*GHz", output)
    encryption_on = re.search(r"Encryption key:(?P<state>\w+)", output)
    encryption = "UNKNOWN"
    if encryption_on:
        encryption = "UNKNOWN" if encryption_on.group("state").lower() == "on" else "OPEN"

    return WiFiInfo(
        ssid=ssid,
        encryption=encryption,
        signal_dbm=_int_or_none(signal_match.group("signal") if signal_match else ""),
        band=_band_from_frequency(frequency_match.group("freq") if frequency_match else ""),
        hidden=False,
    )


def _darwin_wifi_security() -> WiFiInfo | None:
    airport_output = _run_text([_AIRPORT, "-I"])
    ssid = _airport_field(airport_output, "SSID")

    wdutil_output = ""
    if not ssid:
        wdutil_output = _run_text(["wdutil", "info"])
        wdutil_info = _parse_wdutil_info(wdutil_output)
        if wdutil_info:
            return wdutil_info

    if not ssid:
        for interface in _darwin_wifi_interfaces():
            networksetup = _run_text(["networksetup", "-getairportnetwork", interface])
            if ":" in networksetup:
                ssid = networksetup.split(":", 1)[1].strip()
                break
    if not ssid:
        return None

    channel = _airport_field(airport_output, "channel")
    signal = _airport_field(airport_output, "agrCtlRSSI")
    security = _darwin_security_for_ssid(ssid) or _wdutil_field(wdutil_output, "Security")

    return WiFiInfo(
        ssid=ssid,
        encryption=_normalise_encryption(security),
        signal_dbm=_int_or_none(signal),
        band=_band_from_channel(channel),
        hidden=False,
    )


def _airport_field(output: str, name: str) -> str:
    pattern = rf"^\s*{re.escape(name)}:\s*(.+?)\s*$"
    match = re.search(pattern, output, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def _parse_wdutil_info(output: str) -> WiFiInfo | None:
    ssid = _wdutil_field(output, "SSID")
    if not ssid:
        return None

    return WiFiInfo(
        ssid=ssid,
        encryption=_normalise_encryption(_wdutil_field(output, "Security")),
        signal_dbm=_int_or_none(_wdutil_field(output, "RSSI").replace("dBm", "")),
        band=_band_from_channel(_wdutil_field(output, "Channel")),
        hidden=False,
    )


def _wdutil_field(output: str, name: str) -> str:
    pattern = rf"^\s*{re.escape(name)}\s*:\s*(.+?)\s*$"
    match = re.search(pattern, output or "", flags=re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _darwin_wifi_interfaces() -> list[str]:
    output = _run_text(["networksetup", "-listallhardwareports"])
    interfaces: list[str] = []
    current_port = ""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Hardware Port:"):
            current_port = stripped.split(":", 1)[1].strip().lower()
        elif stripped.startswith("Device:") and current_port in {"wi-fi", "airport"}:
            interfaces.append(stripped.split(":", 1)[1].strip())

    if "en0" not in interfaces:
        interfaces.append("en0")
    return interfaces


def _darwin_security_for_ssid(ssid: str) -> str:
    if not Path(_AIRPORT).exists():
        return ""

    output = _run_text([_AIRPORT, "-s"])
    for line in output.splitlines():
        if ssid not in line:
            continue
        security_match = re.search(r"\s(WPA3|WPA2|WPA|WEP|NONE|OPEN)(?:\(|\s|$)", line, re.IGNORECASE)
        if security_match:
            return security_match.group(1)
    return ""


def _windows_wifi_security() -> WiFiInfo | None:
    output = _run_text(["netsh", "wlan", "show", "interfaces"])
    ssid = _netsh_field(output, "SSID")
    if not ssid:
        return None

    return WiFiInfo(
        ssid=ssid,
        encryption=_normalise_encryption(_netsh_field(output, "Authentication")),
        signal_dbm=_signal_percent_to_dbm(_netsh_field(output, "Signal")),
        band=_band_from_channel(_netsh_field(output, "Channel")),
        hidden=False,
    )


def _netsh_field(output: str, name: str) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith(name.lower()) or ":" not in stripped:
            continue
        return stripped.split(":", 1)[1].strip()
    return ""


def _normalise_encryption(value: str) -> str:
    upper = (value or "").upper()
    if not upper or upper in {"--", "NONE", "OPEN", "ESS"}:
        return "OPEN"
    if "WPA3" in upper:
        return "WPA3"
    if "WPA2" in upper or "RSN" in upper:
        return "WPA2"
    if "WPA" in upper:
        return "WPA"
    if "WEP" in upper:
        return "WEP"
    return "UNKNOWN"


def _signal_percent_to_dbm(value: str) -> int | None:
    cleaned = (value or "").strip().rstrip("%")
    try:
        percent = int(cleaned)
    except ValueError:
        return None
    percent = max(0, min(100, percent))
    return int((percent / 2) - 100)


def _band_from_frequency(value: str):
    try:
        frequency = float((value or "").replace("MHz", "").replace("GHz", "").strip())
    except ValueError:
        return "UNKNOWN"
    if frequency > 1000:
        frequency = frequency / 1000
    if 2.3 <= frequency < 2.6:
        return "2.4GHz"
    if 4.9 <= frequency < 5.9:
        return "5GHz"
    if 5.9 <= frequency < 7.2:
        return "6GHz"
    return "UNKNOWN"


def _band_from_channel(value: str):
    lower = (value or "").lower().replace(" ", "")
    if "2.4ghz" in lower or "2ghz" in lower:
        return "2.4GHz"
    if "5ghz" in lower:
        return "5GHz"
    if "6ghz" in lower:
        return "6GHz"

    match = re.search(r"\d+", value or "")
    if not match:
        return "UNKNOWN"
    channel = int(match.group(0))
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    return "UNKNOWN"


def _int_or_none(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _run_text(args: list[str]) -> str:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout
