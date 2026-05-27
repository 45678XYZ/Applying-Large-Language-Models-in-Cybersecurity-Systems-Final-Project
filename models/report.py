"""Top-level scan-report schemas — what the Agent ultimately emits."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .device import Device
from .network import NetworkInfo, RouterInfo, WiFiInfo
from .vulnerability import CVE

Severity = Literal["high", "medium", "low", "info"]
Grade = Literal["A", "B", "C", "D", "F"]
RiskDimension = Literal[
    "router_vulnerability",
    "wifi_encryption",
    "iot_exposure",
    "network_isolation",
    "remote_attack_surface",
]


class RiskFinding(BaseModel):
    """One individual risk item surfaced by the Agent."""

    dimension: RiskDimension
    severity: Severity
    title: str
    description: str
    affected: str | None = None
    related_cves: list[CVE] = Field(default_factory=list)
    recommendation: str


class ScanReport(BaseModel):
    """The full security-health report shown to the user."""

    generated_at: datetime = Field(default_factory=datetime.now)
    network: NetworkInfo
    wifi: WiFiInfo | None = None
    router: RouterInfo | None = None
    devices: list[Device] = Field(default_factory=list)
    findings: list[RiskFinding] = Field(default_factory=list)
    overall_grade: Grade = "C"
    summary_markdown: str = ""
