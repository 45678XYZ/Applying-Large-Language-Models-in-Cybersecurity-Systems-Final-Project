"""Risk reasoning over a device's open ports (RAG-backed, deterministic)."""

from __future__ import annotations

from typing import Any, Protocol

from models import Device, Port, RiskDimension, RiskFinding, Severity

_ADMIN_SERVICES = {"http", "https", "ssh", "telnet", "ftp", "rdp", "vnc"}
_IOT_SERVICES = {"rtsp", "upnp", "ssdp", "mqtt", "coap", "mdns"}

_PORT_BASELINE: dict[int, tuple[Severity, RiskDimension, str, str]] = {
    21: (
        "medium",
        "remote_attack_surface",
        "FTP exposed",
        "Prefer SFTP/SSH, disable anonymous access, and restrict access to trusted hosts.",
    ),
    22: (
        "medium",
        "remote_attack_surface",
        "SSH exposed",
        "Require key-based authentication, disable password login where possible, and restrict management access.",
    ),
    23: (
        "high",
        "remote_attack_surface",
        "Telnet exposed",
        "Disable Telnet and use SSH or HTTPS-only administration instead.",
    ),
    80: (
        "medium",
        "remote_attack_surface",
        "HTTP service exposed",
        "Use HTTPS for administration and limit the interface to the private management network.",
    ),
    135: (
        "high",
        "remote_attack_surface",
        "Windows RPC exposed",
        "Block RPC from untrusted hosts and keep the device fully patched.",
    ),
    139: (
        "high",
        "remote_attack_surface",
        "NetBIOS exposed",
        "Disable legacy file-sharing protocols or isolate them from IoT and guest networks.",
    ),
    443: (
        "low",
        "remote_attack_surface",
        "HTTPS service exposed",
        "Keep firmware and TLS configuration updated, and restrict management access when possible.",
    ),
    445: (
        "high",
        "remote_attack_surface",
        "SMB exposed",
        "Disable SMB where unnecessary, patch the host, and block access outside trusted clients.",
    ),
    554: (
        "high",
        "iot_exposure",
        "RTSP stream exposed",
        "Require authentication, update camera firmware, and isolate camera traffic on a separate VLAN.",
    ),
    1900: (
        "high",
        "iot_exposure",
        "UPnP/SSDP exposed",
        "Disable UPnP unless required and prevent exposure beyond the local trusted subnet.",
    ),
    3389: (
        "high",
        "remote_attack_surface",
        "Remote Desktop exposed",
        "Disable RDP or require VPN/MFA and restrict source IPs.",
    ),
    5000: (
        "medium",
        "iot_exposure",
        "IoT/NAS service exposed",
        "Confirm the service is needed, update firmware, and restrict access by firewall rules.",
    ),
    5353: (
        "low",
        "iot_exposure",
        "mDNS exposed",
        "Limit multicast discovery to trusted LAN segments.",
    ),
    5900: (
        "high",
        "remote_attack_surface",
        "VNC exposed",
        "Disable VNC or require strong authentication over VPN only.",
    ),
    8080: (
        "medium",
        "remote_attack_surface",
        "Alternate web admin port exposed",
        "Move administration behind HTTPS/VPN and restrict access.",
    ),
    8443: (
        "medium",
        "remote_attack_surface",
        "Alternate HTTPS admin port exposed",
        "Restrict administrative access and keep the service patched.",
    ),
}

_HIGH_SIGNAL_TERMS = {
    "default password",
    "weak password",
    "unauthorized",
    "remote code execution",
    "rce",
    "telnet",
    "exposed",
}
_MEDIUM_SIGNAL_TERMS = {
    "insecure",
    "misconfiguration",
    "credential",
    "authentication",
    "firmware",
    "privacy",
}


class PortRiskRetriever(Protocol):
    """Retriever surface frozen at SYNC 1."""

    def lookup_port_risk(
        self,
        port: int,
        service: str | None = None,
        k: int = 5,
    ) -> list[dict[str, Any]]:
        ...


def check_open_ports_risk(
    device: Device,
    retriever: PortRiskRetriever | None = None,
    *,
    k: int = 5,
) -> list[RiskFinding]:
    """Assess every open port on `device` and return structured findings.

    The default path builds B's `rag.Retriever` and calls
    `lookup_port_risk(port, service, k)`. Tests may inject a fake retriever to
    keep this scanner fully offline.
    """
    open_ports = [port for port in device.ports if port.state == "open"]
    if not open_ports:
        return []

    retriever = retriever or _build_default_retriever()
    findings: list[RiskFinding] = []
    for port in open_ports:
        hits = retriever.lookup_port_risk(port.number, service=port.service, k=k)
        findings.append(_finding_from_port(device, port, hits))
    return findings


def _build_default_retriever() -> PortRiskRetriever:
    from rag import build_default_retriever

    return build_default_retriever()


def _finding_from_port(
    device: Device,
    port: Port,
    hits: list[dict[str, Any]],
) -> RiskFinding:
    severity, dimension, title, recommendation = _baseline_for(port, device)
    severity = _adjust_severity(severity, hits)

    affected = _affected_label(device, port)
    source_line = _source_line(hits)
    context = _context_excerpt(hits)

    description = (
        f"{affected} exposes {_service_label(port)}. "
        f"{_risk_sentence(severity, dimension)}"
    )
    if context:
        description += f" Retrieved KB context: {context}"
    if source_line:
        description += f" Sources: {source_line}."

    return RiskFinding(
        dimension=dimension,
        severity=severity,
        title=title,
        description=description,
        affected=affected,
        recommendation=recommendation,
    )


def _baseline_for(port: Port, device: Device) -> tuple[Severity, RiskDimension, str, str]:
    baseline = _PORT_BASELINE.get(port.number)
    if baseline is not None:
        return baseline

    service = (port.service or "").lower()
    if service in _IOT_SERVICES or _looks_like_iot(device):
        return (
            "medium",
            "iot_exposure",
            f"{_display_service(port)} exposed",
            "Confirm the service is required, update firmware, and isolate IoT devices from trusted clients.",
        )
    if service in _ADMIN_SERVICES:
        return (
            "medium",
            "remote_attack_surface",
            f"{_display_service(port)} management exposed",
            "Restrict management access to trusted hosts and require strong authentication.",
        )
    return (
        "low",
        "remote_attack_surface",
        f"Open {_display_service(port)} port",
        "Verify the service is expected, patched, and reachable only from trusted network segments.",
    )


def _adjust_severity(base: Severity, hits: list[dict[str, Any]]) -> Severity:
    text = " ".join(str(hit.get("text", "")) for hit in hits).lower()
    if any(term in text for term in _HIGH_SIGNAL_TERMS):
        return _max_severity(base, "high")
    if any(term in text for term in _MEDIUM_SIGNAL_TERMS):
        return _max_severity(base, "medium")
    return base


def _max_severity(a: Severity, b: Severity) -> Severity:
    order: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}
    return a if order[a] >= order[b] else b


def _risk_sentence(severity: Severity, dimension: RiskDimension) -> str:
    if severity == "high":
        return "This is a high-priority exposure because the service is commonly abused when reachable on a LAN."
    if severity == "medium":
        return "This increases the device's attack surface and should be reviewed before the final report."
    if dimension == "iot_exposure":
        return "This is mainly a discovery or IoT segmentation concern unless the service lacks authentication."
    return "This appears lower risk, but it should still match an intentional service policy."


def _looks_like_iot(device: Device) -> bool:
    text = " ".join(
        value
        for value in [device.vendor, device.hostname, device.os_guess, device.device_type]
        if value
    ).lower()
    return any(
        token in text
        for token in [
            "camera",
            "iot",
            "hikvision",
            "dahua",
            "tuya",
            "arlo",
            "wyze",
            "nas",
            "synology",
        ]
    )


def _service_label(port: Port) -> str:
    parts = [f"{port.protocol}/{port.number}", _display_service(port)]
    product = " ".join(value for value in [port.product, port.version] if value)
    if product:
        parts.append(f"({product})")
    return " ".join(parts)


def _display_service(port: Port) -> str:
    return (port.service or "unknown service").upper()


def _affected_label(device: Device, port: Port) -> str:
    name = device.hostname or device.ip
    vendor = f" / {device.vendor}" if device.vendor else ""
    return f"{name}{vendor} port {port.number}/{port.protocol}"


def _source_line(hits: list[dict[str, Any]]) -> str:
    sources: list[str] = []
    for hit in hits:
        filename = str(hit.get("filename") or "").strip()
        source = str(hit.get("source") or "kb").strip()
        label = filename or source
        if label and label not in sources:
            sources.append(label)
        if len(sources) >= 3:
            break
    return ", ".join(sources)


def _context_excerpt(hits: list[dict[str, Any]]) -> str:
    for hit in hits:
        text = " ".join(str(hit.get("text", "")).split())
        if text:
            return text[:260] + ("..." if len(text) > 260 else "")
    return ""
