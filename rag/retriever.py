"""High-level retrieval — what the Agent's tools actually call.

The Retriever sits on top of `VectorStore` and exposes use-case-shaped
methods (CVE lookup, port-risk lookup, generic search) so the Agent code
does not need to know about Chroma internals or metadata filter syntax.
"""

from models import CVE
from .vector_store import VectorStore


class Retriever:
    def __init__(self, cve_store: VectorStore, kb_store: VectorStore) -> None:
        """Two collections: structured CVE data + free-form security KB."""
        raise NotImplementedError

    def lookup_cve(
        self,
        product: str,
        version: str | None = None,
        k: int = 5,
    ) -> list[CVE]:
        """Vendor/model/version → ranked CVEs."""
        raise NotImplementedError

    def lookup_port_risk(self, port: int, service: str | None = None) -> list[str]:
        """Retrieve KB passages relevant to an open port/service."""
        raise NotImplementedError

    def search(self, query: str, k: int = 5) -> list[str]:
        """Generic semantic search over the security KB (used in Q&A)."""
        raise NotImplementedError
