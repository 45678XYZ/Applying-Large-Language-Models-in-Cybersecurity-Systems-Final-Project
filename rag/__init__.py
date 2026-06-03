"""RAG knowledge-base layer — ChromaDB + Azure OpenAI embeddings.

Public surface (the SYNC 1 contract — see `docs/system-design.md` §1.5):
    - `Retriever.lookup_cve(product, version, k, min_cvss)` — product → CVE list
    - `Retriever.lookup_port_risk(port, service, k)` — open port → KB passages
    - `Retriever.search(query, k)` — generic semantic search (Q&A)
    - `build_default_retriever()` — factory wired from settings
"""

from .retriever import Retriever, build_default_retriever
from .vector_store import VectorStore

__all__ = ["Retriever", "VectorStore", "build_default_retriever"]
