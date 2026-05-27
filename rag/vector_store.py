"""ChromaDB persistence + collection management."""

from pathlib import Path
from typing import Any

from .embeddings import EmbeddingClient


class VectorStore:
    """Owns a single ChromaDB collection's lifecycle."""

    def __init__(
        self,
        persist_path: Path,
        collection_name: str,
        embedder: EmbeddingClient,
    ) -> None:
        raise NotImplementedError

    def add(
        self,
        ids: list[str],
        documents: list[str],
        metadatas: list[dict[str, Any]],
    ) -> None:
        """Insert pre-chunked documents; embeddings computed lazily."""
        raise NotImplementedError

    def query(
        self,
        query_text: str,
        k: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Return top-k hits with text + metadata + score."""
        raise NotImplementedError
