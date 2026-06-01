"""ChromaDB persistence + collection management.

Wraps a single Chroma collection so each domain (CVE / KB) gets its own
`VectorStore` instance. Embeddings flow through an injected
`EmbeddingClient`; Chroma's built-in default embedder is bypassed entirely.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import chromadb
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

from .embeddings import EmbeddingClient


class VectorStore:
    """One Chroma collection's lifecycle, scoped to a single project domain."""

    def __init__(
        self,
        persist_path: Path,
        collection_name: str,
        embedder: EmbeddingClient,
    ) -> None:
        persist_path.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(persist_path))
        # `hnsw:space=cosine` overrides Chroma's L2 default — cosine is the
        # standard distance for OpenAI / Azure embeddings.
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            embedding_function=_ClientAdapter(embedder),
            metadata={"hnsw:space": "cosine"},
        )

    def add(
        self,
        ids: list[str],
        documents: list[str],
        metadatas: list[dict[str, Any]],
    ) -> None:
        """Upsert pre-chunked documents; embeddings are computed by Chroma
        via the injected `EmbeddingClient`. Re-running with the same id
        overwrites — safe for idempotent KB rebuilds.
        """
        if not (len(ids) == len(documents) == len(metadatas)):
            raise ValueError("ids, documents, metadatas must be the same length")
        if not ids:
            return
        self._collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

    def query(
        self,
        query_text: str,
        k: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Return top-k hits, each: `{id, text, metadata, distance}`.

        `distance` follows cosine semantics: smaller is more similar.
        `where` is passed through to Chroma's metadata filter language.
        """
        result = self._collection.query(
            query_texts=[query_text],
            n_results=k,
            where=where,
        )
        return _flatten_single_query(result)

    def count(self) -> int:
        return self._collection.count()


class _ClientAdapter(EmbeddingFunction):
    """Bridge between our `EmbeddingClient` and Chroma's protocol."""

    def __init__(self, client: EmbeddingClient) -> None:
        self._client = client

    def __call__(self, input: Documents) -> Embeddings:
        return self._client.embed_documents(list(input))


def _flatten_single_query(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Chroma returns lists-of-lists (one inner list per query). We always
    issue a single query, so we unwrap the outer dimension.
    """
    ids = (raw.get("ids") or [[]])[0]
    documents = (raw.get("documents") or [[]])[0]
    metadatas = (raw.get("metadatas") or [[]])[0]
    distances = (raw.get("distances") or [[]])[0]
    return [
        {
            "id": _id,
            "text": doc or "",
            "metadata": meta or {},
            "distance": dist,
        }
        for _id, doc, meta, dist in zip(ids, documents, metadatas, distances)
    ]
