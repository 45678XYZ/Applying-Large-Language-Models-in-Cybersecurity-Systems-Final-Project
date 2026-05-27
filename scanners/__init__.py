"""Tool-execution layer — raw scanning capabilities exposed to the Agent.

Each module here MUST return a Pydantic model from `models/` so the Agent
gets structured data, not raw command output.
"""

from .network_info import get_network_info
from .nmap_scanner import scan_network
from .port_risk import check_open_ports_risk
from .router_probe import check_router_info
from .wifi_security import get_wifi_security

__all__ = [
    "check_open_ports_risk",
    "check_router_info",
    "get_network_info",
    "get_wifi_security",
    "scan_network",
]
