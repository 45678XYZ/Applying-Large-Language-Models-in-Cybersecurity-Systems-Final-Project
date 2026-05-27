"""Visual rendering of a `ScanReport` inside Streamlit."""

from models import ScanReport


def render_report(report: ScanReport) -> None:
    """Render the overall grade, per-device table, and risk findings."""
    raise NotImplementedError
