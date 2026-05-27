"""Document chunking strategy for the RAG pipeline."""


def chunk_text(text: str, chunk_size: int = 800, overlap: int = 120) -> list[str]:
    """Split `text` into overlapping windows suitable for embedding."""
    raise NotImplementedError
