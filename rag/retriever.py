"""High-level retrieval — what the Agent's tools and scanners actually call.

The Retriever sits on top of two `VectorStore` collections (`cve` for NVD
records, `kb_docs` for OWASP/NIST/CIS prose) and exposes use-case-shaped
methods so downstream code does not need to know about Chroma internals,
embedding details, or chunk-level mechanics.

This module is also the contract surface for the Phase 2 SYNC 1 point in
`docs/system-design.md` — A's `port_risk.py` and B's `agent/tools.py` both
call methods declared here.
"""

from __future__ import annotations

from typing import Any

from config import settings
from models import CVE

from .vector_store import VectorStore


class Retriever:
    def __init__(self, cve_store: VectorStore, kb_store: VectorStore) -> None:
        """Two collections: structured CVE data + free-form security KB."""
        self._cve_store = cve_store
        self._kb_store = kb_store

    # ── CVE-side ─────────────────────────────────────────────────────────

    def lookup_cve(
        self,
        product: str,
        version: str | None = None,
        k: int = 5,
        min_cvss: float | None = None,
    ) -> list[CVE]:
        """Find CVEs matching `product` (optionally narrowed by `version`).

        Over-fetches by 3× to absorb the case where a single CVE's chunks
        all rank in the top-k; results are deduped by `cve_id` so each CVE
        appears at most once. Reconstructed `CVE` objects use metadata for
        structured fields and the chunk body for `description`.
        """
        query = f"{product} {version}".strip() if version else product
        where = {"cvss_score": {"$gte": min_cvss}} if min_cvss is not None else None

        hits = self._cve_store.query(query, k=k * 3, where=where)
        return _dedupe_cve_hits(hits, k)

    # ── KB-side ──────────────────────────────────────────────────────────

    def lookup_port_risk(
        self,
        port: int,
        service: str | None = None,
        k: int = 5,
    ) -> list[dict[str, Any]]:
        """Retrieve KB passages relevant to an open port / service.

        Returned hits include `text`, `source` (owasp / nist / …),
        `filename`, and `distance` — enough for the caller to do source
        attribution in a `RiskFinding`.
        """
        service = service.strip() if service else ""
        query = f"port {port} {service} insecure service exposed security risk".strip()
        return [_kb_hit(h) for h in self._kb_store.query(query, k=k)]

    def search(self, query: str, k: int = 5) -> list[dict[str, Any]]:
        """Generic semantic search over the security KB (used in Q&A)."""
        return [_kb_hit(h) for h in self._kb_store.query(query, k=k)]


def build_default_retriever() -> Retriever:
    """Construct a Retriever wired up from project settings.

    Uses the default Azure embedder and both Chroma collections that
    `scripts/build_kb.py` produces (`cve` and `kb_docs`).
    """
    from .embeddings import build_default_embedder

    embedder = build_default_embedder()
    cve_store = VectorStore(settings.vector_db_path, "cve", embedder)
    kb_store = VectorStore(settings.vector_db_path, "kb_docs", embedder)
    return Retriever(cve_store, kb_store)


# ── helpers ──────────────────────────────────────────────────────────────


def _dedupe_cve_hits(hits: list[dict[str, Any]], k: int) -> list[CVE]:
    """Collapse chunks of the same CVE into one ranked result list."""
    seen: set[str] = set()
    out: list[CVE] = []
    for hit in hits:
        meta = hit.get("metadata") or {}
        cve_id = meta.get("cve_id")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        out.append(_hit_to_cve(hit))
        if len(out) >= k:
            break
    return out


def _hit_to_cve(hit: dict[str, Any]) -> CVE:
    meta = hit.get("metadata") or {}
    return CVE(
        cve_id=meta["cve_id"],
        cvss_score=meta.get("cvss_score"),
        cvss_severity=meta.get("severity"),
        description=_extract_description(hit.get("text", "")),
        published=meta.get("published"),
    )


def _extract_description(text: str) -> str:
    """Strip the `_cve_to_text` envelope (id + CVSS + affected) and keep the body."""
    body: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("CVE-") and len(stripped) < 25:
            continue
        if stripped.startswith("CVSS "):
            continue
        if stripped.startswith("Affected:"):
            break
        body.append(line)
    cleaned = "\n".join(body).strip()
    return cleaned or text


def _kb_hit(hit: dict[str, Any]) -> dict[str, Any]:
    """Project a raw VectorStore hit into the public KB-hit shape."""
    meta = hit.get("metadata") or {}
    return {
        "text": hit.get("text", ""),
        "source": meta.get("source", "kb"),
        "filename": meta.get("filename", ""),
        "distance": hit.get("distance"),
    }
