"""Local-host network, Wi-Fi, and router probe schemas."""

from typing import Literal

from pydantic import BaseModel, Field

WifiEncryption = Literal["WPA3", "WPA2", "WPA", "WEP", "OPEN", "UNKNOWN"]


class NetworkInfo(BaseModel):
    """Output of `get_network_info` — local host's view of the network."""

    local_ip: str
    subnet_cidr: str
    gateway: str
    dns_servers: list[str] = Field(default_factory=list)
    interface: str
    is_wireless: bool


class WiFiInfo(BaseModel):
    """Output of `get_wifi_security`."""

    ssid: str | None = None
    encryption: WifiEncryption = "UNKNOWN"
    signal_dbm: int | None = None
    band: Literal["2.4GHz", "5GHz", "6GHz", "UNKNOWN"] = "UNKNOWN"
    hidden: bool = False


class RouterInfo(BaseModel):
    """Output of `check_router_info` — gateway-specific probes."""

    gateway_ip: str
    model: str | None = None
    firmware_version: str | None = None
    http_server_header: str | None = None
    admin_panel_exposed: bool = False
    upnp_enabled: bool | None = None
    telnet_open: bool | None = None
    ssh_open: bool | None = None
    dns_rebinding_protection: bool | None = None
