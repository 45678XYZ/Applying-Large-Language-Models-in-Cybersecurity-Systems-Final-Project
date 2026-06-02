"""Layer 4: gateway-specific HTTP probe and feature detection."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from models import RouterInfo


@dataclass
class HttpProbeResult:
    url: str
    status_code: int
    server_header: str | None = None
    title: str | None = None
    body_excerpt: str = ""


def check_router_info(gateway_ip: str) -> RouterInfo:
    """Probe the gateway over HTTP/HTTPS and known feature ports.

    Extracts vendor/model hints from HTTP headers and page title, fingerprints
    firmware-like strings, and checks admin-panel, UPnP, Telnet, and SSH
    exposure. All probes are best-effort and return ``None`` for inconclusive
    feature checks.
    """

    http_results = [
        result for scheme in ("http", "https") if (result := _http_probe(gateway_ip, scheme))
    ]
    primary = http_results[0] if http_results else None
    combined_text = " ".join(
        part
        for result in http_results
        for part in (result.title, result.server_header, result.body_excerpt)
        if part
    )

    return RouterInfo(
        gateway_ip=gateway_ip,
        model=_extract_model_hint(combined_text),
        firmware_version=_extract_firmware_version(combined_text),
        http_server_header=primary.server_header if primary else None,
        admin_panel_exposed=any(_looks_like_admin_panel(result) for result in http_results),
        upnp_enabled=_probe_upnp(gateway_ip),
        telnet_open=_is_tcp_open(gateway_ip, 23),
        ssh_open=_is_tcp_open(gateway_ip, 22),
        dns_rebinding_protection=None,
    )


def _http_probe(gateway_ip: str, scheme: str) -> HttpProbeResult | None:
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - environment dependent.
        raise RuntimeError("requests is required for check_router_info().") from exc

    try:
        response = requests.get(
            f"{scheme}://{gateway_ip}/",
            timeout=4,
            verify=False,
            allow_redirects=True,
        )
    except requests.RequestException:
        return None

    text = response.text[:4096] if response.text else ""
    return HttpProbeResult(
        url=response.url,
        status_code=response.status_code,
        server_header=response.headers.get("Server"),
        title=_extract_title(text),
        body_excerpt=re.sub(r"\s+", " ", text)[:1000],
    )


def _extract_title(html: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", html or "", flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip() or None


def _looks_like_admin_panel(result: HttpProbeResult) -> bool:
    if result.status_code >= 500:
        return False
    text = " ".join(filter(None, [result.title, result.body_excerpt])).lower()
    admin_terms = ("router", "gateway", "login", "admin", "password", "firmware", "management")
    return any(term in text for term in admin_terms)


def _extract_model_hint(text: str) -> str | None:
    if not text:
        return None

    patterns = [
        r"\b((?:TP-Link|D-Link|NETGEAR|ASUS|Linksys|Synology|Ubiquiti|MikroTik|Huawei|Zyxel|Tenda|Xiaomi)[\w\s./-]{0,40})",
        r"\b((?:Archer|Nighthawk|RT-|DIR-|EAP|Deco|Orbi|UniFi|Keenetic|FRITZ!Box)[\w\s./-]{0,35})",
        r"\bModel(?:\s+Name|\s+Number)?\s*[:=-]\s*([A-Za-z0-9][\w ./-]{1,40})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return _clean_hint(match.group(1))
    return None


def _extract_firmware_version(text: str) -> str | None:
    if not text:
        return None

    patterns = [
        r"\bFirmware(?:\s+Version)?\s*[:=-]\s*([A-Za-z0-9._-]+)",
        r"\bVersion\s*[:=-]\s*([A-Za-z0-9._-]+)",
        r"\bBuild\s*[:=-]\s*([A-Za-z0-9._-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def _clean_hint(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value)
    cleaned = re.split(
        r"\b(?:Login|Admin|Password|Firmware|Version|Build|Web Server|Management)\b",
        cleaned,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0]
    return cleaned.strip(" -_/")


def _is_tcp_open(host: str, port: int) -> bool | None:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except (TimeoutError, OSError):
        return False


def _probe_upnp(gateway_ip: str) -> bool | None:
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: upnp:rootdevice\r\n\r\n"
    ).encode("ascii")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.settimeout(2)
            sock.sendto(message, ("239.255.255.250", 1900))
            while True:
                data, address = sock.recvfrom(2048)
                if address[0] == gateway_ip and b"upnp:rootdevice" in data.lower():
                    return True
    except socket.timeout:
        return False
    except OSError:
        return None
