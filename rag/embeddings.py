"""Embedding provider — wraps Azure OpenAI text-embedding-3-small."""


class EmbeddingClient:
    """Thin adapter so the vector store stays embedding-provider agnostic."""

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError

    def embed_query(self, text: str) -> list[float]:
        raise NotImplementedError
