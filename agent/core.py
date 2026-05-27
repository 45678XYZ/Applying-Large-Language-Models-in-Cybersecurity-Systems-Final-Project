"""LangChain Tool-Calling Agent — top-level orchestrator.

Holds the LLM, tool list, system prompt, and conversation memory. Drives
the two modes the system supports:

    1. `run_full_scan()`   — autonomous tool chain → `ScanReport`
    2. `ask(question)`     — Q&A grounded in the prior scan + RAG
"""

from typing import TYPE_CHECKING

from models import ScanReport
from rag import Retriever

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel


class SecurityAgent:
    def __init__(
        self,
        llm: "BaseChatModel",
        retriever: Retriever,
    ) -> None:
        """Wire LLM + tools + memory; nothing is executed yet."""
        raise NotImplementedError

    def run_full_scan(self) -> ScanReport:
        """Kick off the autonomous scan → report pipeline.

        The Agent's planned ordering (it may deviate if reasoning suggests so):
            network_info → wifi_security → scan_network → router_probe
            → lookup_cve (per device) → check_open_ports_risk → report
        """
        raise NotImplementedError

    def ask(self, question: str) -> str:
        """Answer a follow-up question using the most recent ScanReport
        plus newly retrieved KB context.
        """
        raise NotImplementedError
