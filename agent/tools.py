"""LangChain Tool wrappers around the scanners + retriever.

Each function here is decorated with `@tool` (or built via `StructuredTool`)
so that the LangChain Tool-Calling Agent can invoke them autonomously.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from rag import Retriever


def build_tools(retriever: "Retriever") -> list["BaseTool"]:
    """Compose every scanner / RAG capability into LangChain `BaseTool`s.

    Returned tools (names match the Agent's planned call sequence):
        - get_network_info
        - get_wifi_security
        - scan_network
        - check_router_info
        - lookup_cve
        - check_open_ports_risk
    """
    raise NotImplementedError
