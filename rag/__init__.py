"""RAG knowledge-base layer — ChromaDB + Azure OpenAI embeddings.

Public surface:
    - `Retriever.lookup_cve(product, version)` — vendor/version → CVE list
    - `Retriever.search(query, k)` — generic semantic search
"""

from .retriever import Retriever, build_default_retriever
from .vector_store import VectorStore

__all__ = ["Retriever", "VectorStore", "build_default_retriever"]
