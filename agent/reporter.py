"""Convert intermediate tool outputs into the final `ScanReport`.

Pure assembly logic — no LLM calls here besides the Markdown summary.
The Agent gives this module:
    - `NetworkInfo`, `WiFiInfo`, `RouterInfo`
    - `list[Device]`
    - `list[RiskFinding]` (already classified per dimension)
and gets back a `ScanReport` ready for the UI.
"""

from models import (
    Device,
    NetworkInfo,
    RiskFinding,
    RouterInfo,
    ScanReport,
    WiFiInfo,
)


def assemble_report(
    network: NetworkInfo,
    wifi: WiFiInfo | None,
    router: RouterInfo | None,
    devices: list[Device],
    findings: list[RiskFinding],
) -> ScanReport:
    """Compute the overall grade, sort findings by severity, render summary."""
    raise NotImplementedError


def grade_from_findings(findings: list[RiskFinding]) -> str:
    """A–F grading rule based on counts/severity of findings."""
    raise NotImplementedError
