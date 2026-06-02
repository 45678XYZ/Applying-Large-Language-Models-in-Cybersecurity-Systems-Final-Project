"""Build the RAG vector DB from raw KB sources.

Pipeline:
    NVD JSONs   ──► cve_to_text ──┐
                                  ├─► chunker ──► AzureOpenAIEmbedder ──► VectorStore("cve")
    OWASP / NIST ─► loader ───────┤                                                       │
                                  └────────────────────────────────► VectorStore("kb") ◄──┘

Two Chroma collections live under `settings.vector_db_path`:
    - `cve` — one chunk per CVE (multi-chunk for long ones), metadata
      keyed by `cve_id`, `severity`, `cvss_score`, `published`.
    - `kb`  — OWASP IoT Top 10, NIST 800-183, NIST IR 8425, …

Re-runs are idempotent: VectorStore uses upsert, so unchanged docs are
silently overwritten.

Usage:
    .venv/bin/python scripts/build_kb.py
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(override=True)

from config import settings  # noqa: E402
from rag.embeddings import build_default_embedder  # noqa: E402
from rag.ingest.chunker import chunk_document, chunk_text  # noqa: E402
from rag.ingest.owasp_loader import load_static_documents  # noqa: E402
from rag.vector_store import VectorStore  # noqa: E402

UPSERT_BATCH = 500
CHUNK_SIZE = 800
CHUNK_OVERLAP = 120


def main() -> None:
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    log = logging.getLogger("build_kb")

    embedder = build_default_embedder()
    raw_dir = settings.knowledge_base_path / "raw"

    log.info("Indexing CVE collection from %s ...", raw_dir / "nvd")
    cve_store = VectorStore(settings.vector_db_path, "cve", embedder)
    if cve_store.count() > 0:
        log.info("  cve already populated (%d); skipping re-index", cve_store.count())
    else:
        cve_chunks = _index_cves(cve_store, raw_dir / "nvd", log)
        log.info("  cve chunks indexed: %d  (collection total: %d)",
                 cve_chunks, cve_store.count())

    log.info("Indexing KB collection from %s ...", raw_dir)
    kb_store = VectorStore(settings.vector_db_path, "kb_docs", embedder)
    if kb_store.count() > 0:
        log.info("  kb_docs already populated (%d); skipping re-index", kb_store.count())
    else:
        kb_chunks = _index_kb(kb_store, raw_dir, log)
        log.info("  kb_docs chunks indexed: %d  (collection total: %d)",
                 kb_chunks, kb_store.count())


def _index_cves(store: VectorStore, nvd_dir: Path, log: logging.Logger) -> int:
    ids: list[str] = []
    docs: list[str] = []
    metas: list[dict[str, Any]] = []
    indexed = 0

    for path in sorted(nvd_dir.glob("CVE-*.json")):
        data = json.loads(path.read_text())
        chunks = chunk_text(_cve_to_text(data), CHUNK_SIZE, CHUNK_OVERLAP)
        for i, chunk in enumerate(chunks):
            ids.append(f"{data['cve_id']}:{i}")
            docs.append(chunk)
            metas.append(_clean({
                "source": "nvd",
                "cve_id": data["cve_id"],
                "cvss_score": data.get("cvss_score"),
                "severity": data.get("cvss_severity") or "UNKNOWN",
                "published": data.get("published"),
                "chunk_index": i,
            }))
        indexed += len(chunks)

        if len(ids) >= UPSERT_BATCH:
            store.add(ids, docs, metas)
            log.info("  CVE batch flushed; cumulative chunks: %d", indexed)
            ids, docs, metas = [], [], []

    if ids:
        store.add(ids, docs, metas)
    return indexed


def _cve_to_text(data: dict) -> str:
    parts: list[str] = [data["cve_id"]]
    score = data.get("cvss_score")
    severity = data.get("cvss_severity") or ""
    if score is not None:
        parts.append(f"CVSS {score} {severity}".strip())
    if data.get("description"):
        parts.append(data["description"])
    if data.get("affected_products"):
        affected = "; ".join(data["affected_products"][:5])
        parts.append(f"Affected: {affected}")
    return "\n".join(parts)


def _index_kb(store: VectorStore, raw_dir: Path, log: logging.Logger) -> int:
    ids: list[str] = []
    docs: list[str] = []
    metas: list[dict[str, Any]] = []
    indexed = 0

    for text, base_meta in load_static_documents(raw_dir):
        # Defense in depth — owasp_loader already skips, but never index CVEs here.
        if base_meta.get("source") == "nvd":
            continue

        for chunk in chunk_document(text, base_meta, CHUNK_SIZE, CHUNK_OVERLAP):
            ids.append(
                f"{base_meta['source']}:{base_meta['filename']}:{chunk.metadata['chunk_index']}"
            )
            docs.append(chunk.text)
            metas.append(_clean(chunk.metadata))
            indexed += 1

        if len(ids) >= UPSERT_BATCH:
            store.add(ids, docs, metas)
            log.info("  KB batch flushed; cumulative chunks: %d", indexed)
            ids, docs, metas = [], [], []

    if ids:
        store.add(ids, docs, metas)
    return indexed


def _clean(meta: dict[str, Any]) -> dict[str, Any]:
    """Chroma rejects None / non-scalar metadata — coerce or drop."""
    cleaned: dict[str, Any] = {}
    for k, v in meta.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            cleaned[k] = v
        else:
            cleaned[k] = str(v)
    return cleaned


if __name__ == "__main__":
    main()
