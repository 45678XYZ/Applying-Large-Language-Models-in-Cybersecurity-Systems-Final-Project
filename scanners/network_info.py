"""Layer 1: local host network configuration discovery.

This module only introspects the current host. It does not connect to any
external service; OS commands are used only to read routing / DNS state.
"""

from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import subprocess
from pathlib import Path

from models import NetworkInfo

try:  # psutil is part of project requirements, but keep scanner import-safe.
    import psutil
except ImportError:  # pragma: no cover - exercised only in minimal envs.
    psutil = None  # type: ignore[assignment]


_IPV4_ZERO = {"0.0.0.0", "127.0.0.1"}
_WIRELESS_NAME_HINTS = ("wi-fi", "wifi", "wireless", "wlan", "802.11", "wlp", "wl")


def get_network_info() -> NetworkInfo:
    """Detect local IP, subnet, default gateway, DNS servers, and interface.

    The detection path follows the proposal's Layer 1 scanner design:
    psutil/socket for interface data, plus native OS routing/DNS commands
    (`ip route`, `route`, `ipconfig`, PowerShell) for gateway and DNS state.
    """

    system = platform.system().lower()
    interfaces = _collect_ipv4_interfaces()
    route = _get_default_route(system)

    interface = route.get("interface") or ""
    local_ip = route.get("local_ip") or ""

    if not interface and local_ip:
        interface = _interface_for_ip(interfaces, local_ip)
    if not local_ip and interface:
        local_ip = interfaces.get(interface, {}).get("ip", "")

    if not local_ip or not interface:
        fallback_interface, fallback = _first_active_ipv4_interface(interfaces)
        interface = interface or fallback_interface
        local_ip = local_ip or fallback.get("ip", "")

    if not local_ip or not interface:
        raise RuntimeError("Unable to determine a non-loopback IPv4 interface.")

    netmask = interfaces.get(interface, {}).get("netmask", "")
    if not netmask and local_ip:
        netmask = _netmask_for_ip(interfaces, local_ip)

    subnet_cidr = _subnet_cidr(local_ip, netmask)
    gateway = route.get("gateway") or ""
    dns_servers = _get_dns_servers(system, interface)

    return NetworkInfo(
        local_ip=local_ip,
        subnet_cidr=subnet_cidr,
        gateway=gateway,
        dns_servers=dns_servers,
        interface=interface,
        is_wireless=_is_wireless_interface(system, interface),
    )


def _collect_ipv4_interfaces() -> dict[str, dict[str, str]]:
    """Return active non-loopback IPv4 interface data keyed by interface name."""

    if psutil is None:
        return _collect_ipv4_interfaces_without_psutil(platform.system().lower())

    stats = psutil.net_if_stats()
    interfaces: dict[str, dict[str, str]] = {}

    for name, addrs in psutil.net_if_addrs().items():
        if stats and name in stats and not stats[name].isup:
            continue

        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            if not ip or ip in _IPV4_ZERO or ip.startswith("169.254."):
                continue
            interfaces[name] = {
                "ip": ip,
                "netmask": addr.netmask or "",
            }
            break

    return interfaces


def _collect_ipv4_interfaces_without_psutil(system: str) -> dict[str, dict[str, str]]:
    if system == "windows":
        return _windows_ipv4_interfaces()
    if system == "linux":
        return _linux_ipv4_interfaces()
    if system == "darwin":
        return _ifconfig_ipv4_interfaces()
    return {}


def _windows_ipv4_interfaces() -> dict[str, dict[str, str]]:
    command = (
        "Get-NetIPAddress -AddressFamily IPv4 "
        "| Where-Object { $_.IPAddress -notlike '127.*' -and "
        "$_.IPAddress -notlike '169.254.*' } "
        "| Select-Object InterfaceAlias,IPAddress,PrefixLength "
        "| ConvertTo-Json -Compress"
    )
    output = _run_text(["powershell", "-NoProfile", "-Command", command])
    if not output.strip():
        return _parse_ipconfig_interfaces(_run_text(["ipconfig", "/all"]))

    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return _parse_ipconfig_interfaces(_run_text(["ipconfig", "/all"]))

    rows = parsed if isinstance(parsed, list) else [parsed]
    interfaces: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("InterfaceAlias") or "")
        ip = str(row.get("IPAddress") or "")
        prefix = row.get("PrefixLength")
        if not name or not _looks_like_ipv4(ip):
            continue
        interfaces[name] = {
            "ip": ip,
            "netmask": _prefix_to_netmask(prefix),
        }
    return interfaces or _parse_ipconfig_interfaces(_run_text(["ipconfig", "/all"]))


def _parse_ipconfig_interfaces(output: str) -> dict[str, dict[str, str]]:
    interfaces: dict[str, dict[str, str]] = {}
    current_adapter = ""
    current_ip = ""
    current_netmask = ""

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        header = re.match(r"^[^\s].*adapter\s+(.+):$", line, re.IGNORECASE)
        if header:
            if current_adapter and current_ip:
                interfaces[current_adapter] = {
                    "ip": current_ip,
                    "netmask": current_netmask,
                }
            current_adapter = header.group(1).strip()
            current_ip = ""
            current_netmask = ""
            continue

        if not current_adapter:
            continue

        if "IPv4 Address" in line:
            current_ip = _clean_ipconfig_value(line)
        elif "Subnet Mask" in line:
            current_netmask = _clean_ipconfig_value(line)

    if current_adapter and current_ip:
        interfaces[current_adapter] = {
            "ip": current_ip,
            "netmask": current_netmask,
        }

    return {
        name: info
        for name, info in interfaces.items()
        if _looks_like_ipv4(info.get("ip", ""))
        and info["ip"] not in _IPV4_ZERO
        and not info["ip"].startswith("169.254.")
    }


def _linux_ipv4_interfaces() -> dict[str, dict[str, str]]:
    output = _run_text(["ip", "-o", "-4", "addr", "show", "up"])
    interfaces: dict[str, dict[str, str]] = {}

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet":
            continue
        name = parts[1].split("@", 1)[0]
        cidr = parts[3]
        try:
            interface = ipaddress.ip_interface(cidr)
        except ValueError:
            continue
        ip = str(interface.ip)
        if ip in _IPV4_ZERO or ip.startswith("169.254."):
            continue
        interfaces[name] = {
            "ip": ip,
            "netmask": str(interface.network.netmask),
        }
    return interfaces


def _ifconfig_ipv4_interfaces() -> dict[str, dict[str, str]]:
    output = _run_text(["ifconfig"])
    interfaces: dict[str, dict[str, str]] = {}
    current = ""

    for line in output.splitlines():
        if line and not line[0].isspace() and ":" in line:
            current = line.split(":", 1)[0]
            continue
        stripped = line.strip()
        if not current or not stripped.startswith("inet "):
            continue

        parts = stripped.split()
        if len(parts) < 2:
            continue
        ip = parts[1]
        if ip in _IPV4_ZERO or ip.startswith("169.254."):
            continue

        netmask = ""
        if "netmask" in parts:
            netmask_value = _token_after(parts, "netmask")
            netmask = _parse_ifconfig_netmask(netmask_value)

        interfaces[current] = {"ip": ip, "netmask": netmask}

    return interfaces


def _get_default_route(system: str) -> dict[str, str]:
    if system == "linux":
        return _linux_default_route()
    if system == "darwin":
        return _darwin_default_route()
    if system == "windows":
        return _windows_default_route()
    return {}


def _linux_default_route() -> dict[str, str]:
    output = _run_text(["ip", "-4", "route", "show", "default"])
    for line in output.splitlines():
        tokens = line.split()
        if not tokens or tokens[0] != "default":
            continue
        return {
            "gateway": _token_after(tokens, "via"),
            "interface": _token_after(tokens, "dev"),
            "local_ip": _token_after(tokens, "src"),
        }
    return {}


def _darwin_default_route() -> dict[str, str]:
    output = _run_text(["route", "-n", "get", "default"])
    route: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("gateway:"):
            route["gateway"] = line.split(":", 1)[1].strip()
        elif line.startswith("interface:"):
            route["interface"] = line.split(":", 1)[1].strip()
    return route


def _windows_default_route() -> dict[str, str]:
    route = _windows_default_route_powershell()
    if route:
        return route
    return _windows_default_route_print()


def _windows_default_route_powershell() -> dict[str, str]:
    command = (
        "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "| Sort-Object RouteMetric,InterfaceMetric "
        "| Select-Object -First 1 NextHop,InterfaceAlias; "
        "if ($r) { $r | ConvertTo-Json -Compress }"
    )
    output = _run_text(["powershell", "-NoProfile", "-Command", command])
    if not output.strip():
        return {}

    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return {}

    gateway = str(parsed.get("NextHop") or "")
    interface = str(parsed.get("InterfaceAlias") or "")
    if not gateway or gateway == "0.0.0.0":
        return {}
    return {"gateway": gateway, "interface": interface}


def _windows_default_route_print() -> dict[str, str]:
    output = _run_text(["route", "print", "-4"])
    candidates: list[tuple[int, str, str]] = []

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
            continue
        gateway, local_ip = parts[2], parts[3]
        try:
            metric = int(parts[4])
        except ValueError:
            metric = 9999
        if gateway not in _IPV4_ZERO and local_ip not in _IPV4_ZERO:
            candidates.append((metric, gateway, local_ip))

    if not candidates:
        return {}

    _, gateway, local_ip = sorted(candidates, key=lambda item: item[0])[0]
    return {"gateway": gateway, "local_ip": local_ip}


def _get_dns_servers(system: str, interface: str) -> list[str]:
    if system == "windows":
        servers = _windows_dns_servers(interface)
    elif system == "darwin":
        servers = _darwin_dns_servers()
    else:
        servers = _resolv_conf_dns_servers()

    return _dedupe_ipv4(servers)


def _resolv_conf_dns_servers() -> list[str]:
    resolv_conf = Path("/etc/resolv.conf")
    if not resolv_conf.exists():
        return []

    servers: list[str] = []
    try:
        for line in resolv_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped.startswith("nameserver"):
                parts = stripped.split()
                if len(parts) >= 2:
                    servers.append(parts[1])
    except OSError:
        return []
    return servers


def _darwin_dns_servers() -> list[str]:
    output = _run_text(["scutil", "--dns"])
    servers: list[str] = []
    for line in output.splitlines():
        match = re.search(r"nameserver\[[0-9]+\]\s*:\s*(\S+)", line)
        if match:
            servers.append(match.group(1))
    return servers or _resolv_conf_dns_servers()


def _windows_dns_servers(interface: str) -> list[str]:
    command = (
        "$items=Get-DnsClientServerAddress -AddressFamily IPv4 "
        "| Where-Object { $_.ServerAddresses.Count -gt 0 } "
        "| Select-Object InterfaceAlias,ServerAddresses; "
        "$items | ConvertTo-Json -Compress"
    )
    output = _run_text(["powershell", "-NoProfile", "-Command", command])
    servers = _parse_windows_dns_json(output, interface)
    if servers:
        return servers
    return _parse_ipconfig_dns(_run_text(["ipconfig", "/all"]), interface)


def _parse_windows_dns_json(output: str, interface: str) -> list[str]:
    if not output.strip():
        return []

    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        return []

    rows = parsed if isinstance(parsed, list) else [parsed]
    preferred: list[str] = []
    all_servers: list[str] = []

    for row in rows:
        if not isinstance(row, dict):
            continue
        row_servers = row.get("ServerAddresses") or []
        if isinstance(row_servers, str):
            row_servers = [row_servers]
        alias = str(row.get("InterfaceAlias") or "")
        all_servers.extend(row_servers)
        if interface and alias.lower() == interface.lower():
            preferred.extend(row_servers)

    return preferred or all_servers


def _parse_ipconfig_dns(output: str, interface: str) -> list[str]:
    servers: list[str] = []
    current_adapter = ""
    collecting_dns = False

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        header = re.match(r"^[^\s].*adapter\s+(.+):$", line, re.IGNORECASE)
        if header:
            current_adapter = header.group(1).strip()
            collecting_dns = False
            continue

        if interface and current_adapter and interface.lower() not in current_adapter.lower():
            continue

        if "DNS Servers" in line:
            collecting_dns = True
            value = line.split(":", 1)[-1].strip()
            if value:
                servers.append(value)
            continue

        if collecting_dns:
            value = line.strip()
            if _looks_like_ipv4(value):
                servers.append(value)
            elif value:
                collecting_dns = False

    return servers


def _clean_ipconfig_value(line: str) -> str:
    value = line.split(":", 1)[-1].strip()
    return value.split("(", 1)[0].strip()


def _is_wireless_interface(system: str, interface: str) -> bool:
    lower_name = interface.lower()
    if any(hint in lower_name for hint in _WIRELESS_NAME_HINTS):
        return True

    if system == "linux":
        return Path(f"/sys/class/net/{interface}/wireless").exists()
    if system == "darwin":
        return _darwin_wifi_device() == interface
    if system == "windows":
        return _windows_wifi_interface() == lower_name
    return False


def _darwin_wifi_device() -> str:
    output = _run_text(["networksetup", "-listallhardwareports"])
    in_wifi_block = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip().lower()
            in_wifi_block = port in {"wi-fi", "airport"}
        elif in_wifi_block and line.startswith("Device:"):
            return line.split(":", 1)[1].strip()
    return ""


def _windows_wifi_interface() -> str:
    output = _run_text(["netsh", "wlan", "show", "interfaces"])
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("name") and ":" in stripped:
            return stripped.split(":", 1)[1].strip().lower()
    return ""


def _first_active_ipv4_interface(
    interfaces: dict[str, dict[str, str]],
) -> tuple[str, dict[str, str]]:
    for name, info in interfaces.items():
        if info.get("ip"):
            return name, info
    return "", {}


def _interface_for_ip(interfaces: dict[str, dict[str, str]], ip: str) -> str:
    for name, info in interfaces.items():
        if info.get("ip") == ip:
            return name
    return ""


def _netmask_for_ip(interfaces: dict[str, dict[str, str]], ip: str) -> str:
    for info in interfaces.values():
        if info.get("ip") == ip:
            return info.get("netmask", "")
    return ""


def _subnet_cidr(ip: str, netmask: str) -> str:
    if netmask:
        try:
            return str(ipaddress.ip_network(f"{ip}/{netmask}", strict=False))
        except ValueError:
            pass
    return f"{ip}/32"


def _prefix_to_netmask(prefix: object) -> str:
    try:
        prefix_int = int(prefix)
    except (TypeError, ValueError):
        return ""

    if prefix_int < 0 or prefix_int > 32:
        return ""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_int}").netmask)


def _parse_ifconfig_netmask(value: str) -> str:
    if _looks_like_ipv4(value):
        return value

    try:
        as_int = int(value, 16)
    except ValueError:
        return ""
    return str(ipaddress.IPv4Address(as_int))


def _dedupe_ipv4(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().strip(",")
        if not _looks_like_ipv4(cleaned) or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def _looks_like_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _token_after(tokens: list[str], marker: str) -> str:
    try:
        index = tokens.index(marker)
    except ValueError:
        return ""
    if index + 1 >= len(tokens):
        return ""
    return tokens[index + 1]


def _run_text(args: list[str]) -> str:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout
