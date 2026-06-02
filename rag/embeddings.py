"""Embedding provider — wraps Azure OpenAI text-embedding-3-small.

`EmbeddingClient` is the abstract contract VectorStore depends on; swap in
fakes for tests by subclassing. `AzureOpenAIEmbedder` is the production
implementation and `build_default_embedder()` constructs it from settings.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from config import settings

if TYPE_CHECKING:
    from openai import AzureOpenAI

_log = logging.getLogger(__name__)

# Conservative batch — Azure accepts up to 2048 inputs / 8191 tokens per item.
_DEFAULT_BATCH_SIZE = 100
_MAX_RETRIES = 4


class EmbeddingClient:
    """Abstract embedder; VectorStore and tests depend on this surface only."""

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError

    def embed_query(self, text: str) -> list[float]:
        raise NotImplementedError


class AzureOpenAIEmbedder(EmbeddingClient):
    """Azure OpenAI implementation.

    Note: in Azure SDK, `model=` is the *deployment name* you chose in the
    Azure portal — not the underlying model identifier.
    """

    def __init__(
        self,
        deployment: str,
        endpoint: str,
        api_key: str,
        api_version: str,
        batch_size: int = _DEFAULT_BATCH_SIZE,
    ) -> None:
        if not (deployment and endpoint and api_key):
            raise ValueError(
                "AzureOpenAIEmbedder requires deployment, endpoint, and api_key"
            )

        # Import here so tests with FakeEmbedder don't need openai installed.
        from openai import AzureOpenAI

        self._client: AzureOpenAI = AzureOpenAI(
            api_key=api_key,
            api_version=api_version,
            azure_endpoint=endpoint,
        )
        self._deployment = deployment
        self._batch_size = batch_size

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        # Azure rejects empty strings — replace with single space.
        cleaned = [t if t.strip() else " " for t in texts]

        out: list[list[float]] = []
        for i in range(0, len(cleaned), self._batch_size):
            batch = cleaned[i : i + self._batch_size]
            response = self._call_with_retry(batch)
            out.extend(item.embedding for item in response.data)
        return out

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]

    def _call_with_retry(self, batch: list[str]):
        # Only retry transient failures — auth / bad-request errors should
        # surface immediately so the caller can fix config.
        from openai import APIConnectionError, APITimeoutError, InternalServerError, RateLimitError

        retryable = (RateLimitError, APIConnectionError, APITimeoutError, InternalServerError)

        backoff = 2.0
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                return self._client.embeddings.create(
                    model=self._deployment,
                    input=batch,
                )
            except retryable as exc:
                if attempt == _MAX_RETRIES:
                    raise
                _log.warning(
                    "Azure embedding transient error (%s); retrying in %.1fs (%d/%d)",
                    type(exc).__name__,
                    backoff,
                    attempt,
                    _MAX_RETRIES,
                )
                time.sleep(backoff)
                backoff *= 2
        raise RuntimeError("Azure embedding exhausted retries")


def build_default_embedder() -> EmbeddingClient:
    """Construct an `AzureOpenAIEmbedder` from project settings."""
    return AzureOpenAIEmbedder(
        deployment=settings.azure_openai_embedding_deployment,
        endpoint=settings.azure_openai_endpoint,
        api_key=settings.azure_openai_api_key,
        api_version=settings.azure_openai_api_version,
    )
