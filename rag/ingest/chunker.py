"""Document chunking for the RAG pipeline.

Strategy: hierarchical-separator split — try paragraph breaks, then lines,
sentences, words, finally hard char split. Adjacent chunks share a sliding
overlap so semantic context survives the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Order matters: coarsest split first, finest last; "" forces hard char split.
_DEFAULT_SEPARATORS: tuple[str, ...] = ("\n\n", "\n", ". ", " ", "")


@dataclass
class Chunk:
    """A retrieval unit: text plus provenance metadata."""

    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


def chunk_text(
    text: str,
    chunk_size: int = 800,
    overlap: int = 120,
) -> list[str]:
    """Split `text` into windows of at most `chunk_size` chars with overlap."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must satisfy 0 <= overlap < chunk_size")

    cleaned = text.strip()
    if not cleaned:
        return []
    if len(cleaned) <= chunk_size:
        return [cleaned]

    atoms = _recursive_split(cleaned, chunk_size, list(_DEFAULT_SEPARATORS))
    return _merge_with_overlap(atoms, chunk_size, overlap)


def chunk_document(
    text: str,
    metadata: dict[str, Any] | None = None,
    chunk_size: int = 800,
    overlap: int = 120,
) -> list[Chunk]:
    """Chunk `text` and stamp `metadata` (+ chunk_index) onto each result."""
    base = dict(metadata or {})
    pieces = chunk_text(text, chunk_size=chunk_size, overlap=overlap)
    return [
        Chunk(text=piece, metadata={**base, "chunk_index": i})
        for i, piece in enumerate(pieces)
    ]


def _recursive_split(text: str, chunk_size: int, separators: list[str]) -> list[str]:
    """Recursively split with progressively finer separators."""
    if len(text) <= chunk_size:
        return [text] if text else []
    if not separators:
        return _hard_split(text, chunk_size)

    sep = separators[0]
    rest = separators[1:]
    if not sep:
        return _hard_split(text, chunk_size)

    parts: list[str] = []
    for piece in text.split(sep):
        if not piece:
            continue
        if len(piece) <= chunk_size:
            parts.append(piece)
        else:
            parts.extend(_recursive_split(piece, chunk_size, rest))
    return parts


def _hard_split(text: str, chunk_size: int) -> list[str]:
    return [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]


def _merge_with_overlap(
    atoms: list[str],
    chunk_size: int,
    overlap: int,
    separator: str = " ",
) -> list[str]:
    """Greedy merge with sliding-window overlap between adjacent chunks.

    Invariant after each iteration:
        current_len == len(separator.join(current))
    """
    sep_len = len(separator)
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    def shrink_to_overlap() -> None:
        nonlocal current_len
        while current and current_len > overlap:
            first = current.pop(0)
            if current:
                current_len -= len(first) + sep_len
            else:
                current_len = 0

    for atom in atoms:
        added = len(atom) + (sep_len if current else 0)
        if current_len + added > chunk_size and current:
            chunks.append(separator.join(current))
            shrink_to_overlap()
            added = len(atom) + (sep_len if current else 0)

        current.append(atom)
        current_len += added

    if current:
        chunks.append(separator.join(current))
    return chunks
