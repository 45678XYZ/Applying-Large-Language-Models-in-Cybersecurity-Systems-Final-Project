"""Risk reasoning over a device's open ports (RAG + LLM hybrid)."""

from models import Device, RiskFinding


def check_open_ports_risk(device: Device) -> list[RiskFinding]:
    """For each open port on `device`, retrieve relevant KB context and
    return one or more `RiskFinding` items.

    Bridges scanners → rag/retriever → models.RiskFinding. Pure scanning
    layer; the Agent decides whether to call this per device or per service.
    """
    raise NotImplementedError
