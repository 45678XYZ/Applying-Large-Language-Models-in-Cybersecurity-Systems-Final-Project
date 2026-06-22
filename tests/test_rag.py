"""RAG tests — chunker boundaries, retriever filters, embedding mocks.

All offline: the chunker and loaders are pure, the retriever runs on a fake
``VectorStore``, and the embedding contract is exercised without ever touching
Azure or ChromaDB's network/disk paths.
"""

from __future__ import annotations

import pytest

from models import CVE
from rag.embeddings import AzureOpenAIEmbedder, EmbeddingClient
from rag.ingest.chunker import Chunk, chunk_document, chunk_text
from rag.ingest.nvd_loader import _parse_cve
from rag.ingest.owasp_loader import _load_html, load_static_documents
from rag.retriever import Retriever
from rag.vector_store import _ClientAdapter, _flatten_single_query


# ── chunker boundaries ─────────────────────────────────────────────────────


def test_chunk_text_returns_single_chunk_when_short():
    assert chunk_text("  short text  ", chunk_size=800) == ["short text"]


def test_chunk_text_empty_returns_empty():
    assert chunk_text("   ", chunk_size=800) == []


def test_chunk_text_splits_with_bounded_size_and_overlap():
    text = " ".join(f"word{i:02d}" for i in range(50))
    chunks = chunk_text(text, chunk_size=60, overlap=20)

    assert len(chunks) > 1
    assert all(len(c) <= 60 for c in chunks)  # never exceeds chunk_size
    for a, b in zip(chunks, chunks[1:]):  # adjacent chunks overlap
        assert set(a.split()) & set(b.split())
    joined = " ".join(chunks)  # no content lost across the boundaries
    assert all(f"word{i:02d}" in joined for i in range(50))


def test_chunk_text_validates_parameters():
    with pytest.raises(ValueError):
        chunk_text("hi", chunk_size=0)
    with pytest.raises(ValueError):
        chunk_text("hi", chunk_size=10, overlap=10)  # overlap must be < chunk_size


def test_chunk_document_stamps_metadata_and_index():
    text = " ".join(f"tok{i:02d}" for i in range(40))
    chunks = chunk_document(text, metadata={"source": "owasp"}, chunk_size=50, overlap=10)

    assert len(chunks) > 1
    assert all(isinstance(c, Chunk) for c in chunks)
    assert [c.metadata["chunk_index"] for c in chunks] == list(range(len(chunks)))
    assert all(c.metadata["source"] == "owasp" for c in chunks)


# ── retriever filters (fake VectorStore) ────────────────────────────────────


class _FakeStore:
    """Records query calls and returns canned hits — no Chroma, no embedder."""

    def __init__(self, hits):
        self._hits = hits
        self.calls: list[dict] = []

    def query(self, query_text, k=5, where=None):
        self.calls.append({"query": query_text, "k": k, "where": where})
        return list(self._hits)


def test_lookup_cve_builds_query_dedupes_and_reconstructs():
    chunks = [
        {
            "text": "CVE-2023-0001\nCVSS 8.1 HIGH\nReal description one.\nAffected: cpe:x",
            "metadata": {"cve_id": "CVE-2023-0001", "cvss_score": 8.1, "severity": "HIGH", "published": "2023-01-01"},
            "distance": 0.1,
        },
        {  # a second chunk of the SAME CVE — must be collapsed away
            "text": "CVE-2023-0001\nCVSS 8.1 HIGH\nReal description one (other chunk).",
            "metadata": {"cve_id": "CVE-2023-0001"},
            "distance": 0.2,
        },
        {
            "text": "CVE-2023-0002\nCVSS 5.0 MEDIUM\nSecond bug.\nAffected: cpe:y",
            "metadata": {"cve_id": "CVE-2023-0002", "cvss_score": 5.0},
            "distance": 0.3,
        },
    ]
    cve_store = _FakeStore(chunks)
    retr = Retriever(cve_store, _FakeStore([]))

    out = retr.lookup_cve("TP-Link", version="1.2", k=2, min_cvss=7.0)

    call = cve_store.calls[0]
    assert call["query"] == "TP-Link 1.2"
    assert call["k"] == 6  # over-fetch by 3×
    assert call["where"] == {"cvss_score": {"$gte": 7.0}}

    assert [c.cve_id for c in out] == ["CVE-2023-0001", "CVE-2023-0002"]  # deduped
    assert out[0].cvss_score == 8.1
    assert out[0].description == "Real description one."  # envelope stripped


def test_lookup_cve_without_version_or_mincvss_omits_filter():
    cve_store = _FakeStore([])
    retr = Retriever(cve_store, _FakeStore([]))

    retr.lookup_cve("Hikvision")

    call = cve_store.calls[0]
    assert call["query"] == "Hikvision"
    assert call["where"] is None
    assert call["k"] == 15  # default k=5 × 3


def test_lookup_port_risk_builds_query_and_projects_hits():
    kb_store = _FakeStore(
        [{"text": "Telnet is insecure.", "metadata": {"source": "owasp", "filename": "iot.md"}, "distance": 0.4}]
    )
    retr = Retriever(_FakeStore([]), kb_store)

    hits = retr.lookup_port_risk(23, service="telnet")

    assert kb_store.calls[0]["query"] == "port 23 telnet insecure service exposed security risk"
    assert hits == [{"text": "Telnet is insecure.", "source": "owasp", "filename": "iot.md", "distance": 0.4}]


def test_search_projects_kb_hits_with_defaults():
    kb_store = _FakeStore([{"text": "WPA3 guidance.", "metadata": {}, "distance": 0.5}])
    retr = Retriever(_FakeStore([]), kb_store)

    hits = retr.search("how to secure wifi")

    assert kb_store.calls[0]["query"] == "how to secure wifi"
    assert hits[0] == {"text": "WPA3 guidance.", "source": "kb", "filename": "", "distance": 0.5}


# ── vector-store plumbing (the retriever's foundation) ──────────────────────


def test_flatten_single_query_unwraps_chroma_shape():
    raw = {
        "ids": [["a", "b"]],
        "documents": [["da", "db"]],
        "metadatas": [[{"x": 1}, None]],
        "distances": [[0.1, 0.2]],
    }
    assert _flatten_single_query(raw) == [
        {"id": "a", "text": "da", "metadata": {"x": 1}, "distance": 0.1},
        {"id": "b", "text": "db", "metadata": {}, "distance": 0.2},
    ]


def test_flatten_single_query_handles_empty_result():
    assert _flatten_single_query({}) == []


def test_client_adapter_bridges_embedding_client():
    class _Embedder(EmbeddingClient):
        def embed_documents(self, texts):
            return [[float(len(t))] for t in texts]

    adapter = _ClientAdapter(_Embedder())
    assert adapter(["ab", "abc"]) == [[2.0], [3.0]]


# ── embedding mocks ─────────────────────────────────────────────────────────


def test_embedding_client_is_abstract():
    client = EmbeddingClient()
    with pytest.raises(NotImplementedError):
        client.embed_documents(["x"])
    with pytest.raises(NotImplementedError):
        client.embed_query("x")


def test_azure_embedder_requires_credentials():
    # Missing deployment must fail fast, before any openai import / network call.
    with pytest.raises(ValueError):
        AzureOpenAIEmbedder(deployment="", endpoint="https://x", api_key="k", api_version="v")


# ── ingest loaders ──────────────────────────────────────────────────────────


def test_parse_cve_extracts_fields_and_prefers_v31_cvss():
    raw = {
        "id": "CVE-2023-1234",
        "descriptions": [{"lang": "es", "value": "spanish"}, {"lang": "en", "value": "A real flaw."}],
        "metrics": {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"vulnerable": True, "criteria": "cpe:2.3:o:vendor:fw:1.0"},
                            {"vulnerable": False, "criteria": "cpe:2.3:o:vendor:fw:2.0"},
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": "https://example.test"}, {"nourl": True}],
        "published": "2023-05-01T00:00:00",
    }

    cve = _parse_cve(raw)

    assert isinstance(cve, CVE)
    assert cve.cve_id == "CVE-2023-1234"
    assert cve.description == "A real flaw."  # English description picked
    assert cve.cvss_score == 9.8 and cve.cvss_severity == "CRITICAL"  # v3.1 over v2
    assert cve.affected_products == ["cpe:2.3:o:vendor:fw:1.0"]  # only vulnerable CPEs
    assert cve.references == ["https://example.test"]


def test_parse_cve_returns_none_without_id():
    assert _parse_cve({}) is None


def test_load_static_documents_filters_and_labels(tmp_path):
    (tmp_path / "owasp").mkdir()
    (tmp_path / "owasp" / "iot.md").write_text("OWASP IoT guidance.", encoding="utf-8")
    (tmp_path / "owasp" / ".hidden.md").write_text("nope", encoding="utf-8")  # dotfile → skip
    (tmp_path / "owasp" / "empty.txt").write_text("   ", encoding="utf-8")  # blank → skip
    (tmp_path / "nvd").mkdir()
    (tmp_path / "nvd" / "CVE-1.json").write_text("{}", encoding="utf-8")  # nvd json → skip

    docs = list(load_static_documents(tmp_path))

    assert len(docs) == 1
    text, meta = docs[0]
    assert text == "OWASP IoT guidance."
    assert meta == {"source": "owasp", "path": "owasp/iot.md", "filename": "iot.md"}


def test_load_html_strips_tags_and_scripts(tmp_path):
    html = tmp_path / "p.html"
    html.write_text(
        "<html><head><style>.x{}</style><script>bad()</script></head>"
        "<body><h1>Title</h1><p>Body text.</p></body></html>",
        encoding="utf-8",
    )

    out = _load_html(html)

    assert "Title" in out and "Body text." in out
    assert "bad()" not in out and ".x{}" not in out
