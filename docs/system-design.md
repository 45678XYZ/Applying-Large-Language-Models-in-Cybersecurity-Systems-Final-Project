# System Design & Implementation Plan

This document is the **single source of truth** for who builds what, in what
order, and what each task's "done" looks like. For the architectural
overview itself, see [`README.md`](../README.md).

---

## 1. Goal Recap

Deliver an LLM-Agent-driven home network security auditor that, on a single
button press, autonomously scans the LAN, cross-references findings against
a CVE / OWASP knowledge base, produces a graded report, and supports
natural-language Q&A on the results.

---

## 1.5. Status Snapshot (updated 2026-06-03)

```
Phase 0 — Bootstrap                          ✅ DONE
Phase 1 — Foundation
  ├─ A: scanners (5 tasks)                  █████  DONE
  └─ B: RAG knowledge base (6 tasks)        █████  DONE
Phase 2 — Retrieval & Tooling Layer
  ├─ A: scanner enrichment (2 tasks)        ██     DONE
  └─ B: retriever API (4 tasks)             ████   DONE  ← SYNC 1 locked
Phase 3 — Cross-cutting Glue                 in progress
  ├─ A: port_risk.py (1 task)               ░      not started
  └─ B: tools.py + prompts draft (2)        ██     DONE  ← SYNC 2 ready (B side)
Phase 4 — Agent Executor & Report            in progress
  ├─ A: UI shell (3 tasks)                  ░░░    not started
  └─ B: core / reporter / prompt-iter (3)   █░░    reporter DONE (early)
Phase 5–6                                    not started
```

**KB built end-to-end**: 5,355 CVE chunks + 200 KB chunks; semantic +
metadata-filtered retrieval verified on both collections.

**SYNC 1 contract** (Retriever API, frozen for A and B's downstream use):
- `lookup_cve(product, version=None, k=5, min_cvss=None) -> list[CVE]`
- `lookup_port_risk(port, service=None, k=5) -> list[dict]`  (text/source/filename/distance)
- `search(query, k=5) -> list[dict]`  (same shape as lookup_port_risk)
- Factory: `rag.build_default_retriever()`

**§7 open questions still pending.** B's independent Phase 3/4 work has begun
under documented assumptions: prompts use *hybrid autonomy* (tool-calling agent
+ recommended order), and the A–F grade is computed deterministically in
`reporter.py` rather than by the LLM. The autonomous-vs-sequential call should
be finalised with A at **SYNC 2**, before `tools.py`/`core.py` wiring — it is a
prompt-only change to flip.

---

## 2. Team Split

| Member       | Owns                                  | Directories                                     |
| ------------ | ------------------------------------- | ----------------------------------------------- |
| **A** (陳揚盛) | Scanners · Frontend · Testing         | `scanners/`, `ui/`, `tests/`, `utils/oui_lookup` |
| **B** (陳俊瑋) | Agent core · Prompts · RAG knowledge  | `agent/`, `rag/`, `config/prompts.py`, `scripts/` |
| **Shared**   | Data contracts · Settings · Bootstrap | `models/`, `config/settings.py`, `README.md`, `requirements.txt` |

**Rule of thumb**: anything in `models/` is a *contract* between A and B —
changes require a quick sync before merging.

---

## 3. Data-flow & Dependency Map

```
                         (shared models/)
                                │
   ┌──────── A's track ─────────┴─────── B's track ────────┐
   │                                                       │
   network_info ──┬─► nmap_scanner ─┐         NVD fetch ──► chunker
   wifi_security ─┤                 │         OWASP/CIS  ─► chunker
   router_probe ──┘                 │                          │
                                    ▼                          ▼
                              Device list                 vector_store
                                    │                          │
                                    └──────────► port_risk ◄───┤
                                                  (A calls B's retriever)
                                                       │
                                                       ▼
                                          agent/tools.py   ◄── sync point
                                                       │
                                                       ▼
                                                 agent/core
                                                       │
                                                       ▼
                                                 agent/reporter
                                                       │
                                                       ▼
                                               ui/chat + report_view
```

**Critical sync points** (both members must align before crossing):

1. **`models/` finalisation** — before either side codes heavily.
2. **`agent/tools.py`** — B wraps A's scanners as LangChain tools; A must
   keep scanner signatures stable, B must respect Pydantic schemas.
3. **`port_risk.py`** — A's scanner that calls B's `Retriever`; agree on
   the retriever method signature before A implements.

---

## 4. Phase Plan

Each phase lists `A:` and `B:` tasks. Tasks **inside** a phase are
parallel; **between** phases is sequential. Sync points are called out
explicitly.

### Phase 0 — Bootstrap ✅ DONE

- ✅ Project scaffolding (10 commits)
- ✅ Python 3.12 venv via `uv`, dependencies installed
- ✅ `scanners/network_info.py` implemented and smoke-tested

### Phase 1 — Foundation (fully parallel, no blocking)

**A: complete the remaining raw scanners**

- [x] `scanners/wifi_security.py` — nmcli on Linux, `airport`/`networksetup` on macOS
- [x] `scanners/nmap_scanner.py` — host discovery + top-N port scan + `-sV` + `-O`
- [x] `scanners/router_probe.py` — HTTP/HTTPS gateway probe, UPnP/Telnet/SSH checks
- [x] `utils/oui_lookup.py` — MAC → vendor mapping (ship IEEE OUI file under `data/`)
- [x] Per-scanner smoke test: call from REPL and verify `model_dump_json()` output

**B: build the RAG knowledge base** ✅ DONE

- [x] `scripts/fetch_nvd.py` — 5,000 CVEs cached across 12 home-net / IoT vendors (`8f70486`, `98b1d72`)
- [x] `rag/ingest/owasp_loader.py` — markdown + PDF + HTML loader (`da92fc2`)
- [x] `rag/ingest/chunker.py` — hierarchical-separator splitter with sliding overlap (`2434a30`)
- [x] `rag/embeddings.py` — Azure OpenAI client, batching + retry on transient errors (`f00afcd`)
- [x] `rag/vector_store.py` — ChromaDB wrapper, cosine space, upsert semantics (`e68c668`)
- [x] `scripts/build_kb.py` — orchestrates both collections, skip-if-populated guard (`5224fb8`)
- [x] Seed KB content: OWASP IoT Top 10 markdown (`e5487ca`) + 2 NIST PDFs placed under `data/knowledge_base/raw/nist/`

**Notes from the build:** Swapped CIS Router Benchmark for NIST IR 8425
(CIS has no consumer-router doc). Added `pypdf` to requirements.
`load_dotenv(override=True)` in scripts so `.env` wins over stale shell
exports. Chroma collections are `cve` and `kb_docs` (Chroma rejects
collection names shorter than 3 chars).

### Phase 2 — Retrieval & Tooling Layer

**A: enrichment + first scanner integration** — DONE

- [x] Plug `oui_lookup` into `nmap_scanner` output (fills `Device.vendor`)
- [x] Optional: per-device hostname resolution (`socket.gethostbyaddr`)

**B: retriever API** ✅ DONE

- [x] `rag/retriever.py.lookup_cve(product, version, k, min_cvss)` — semantic + CVSS-threshold filter, dedupes by `cve_id` (`07f9f28`)
- [x] `rag/retriever.py.lookup_port_risk(port, service, k)` — port/service-shaped query into kb_docs (`07f9f28`)
- [x] `rag/retriever.py.search(query, k)` — generic Q&A retrieval over kb_docs (`07f9f28`)
- [x] Smoke-tests: 5 scenarios covering TP-Link CVE retrieval, CVSS filter, Telnet/RTSP port risk, KB gap detection

> 🔁 **SYNC 1 — Contract locked.** A's `port_risk.py` and B's `agent/tools.py`
> should both use `rag.build_default_retriever()` and call the signatures
> recorded in §1.5. The Retriever is the only surface allowed to touch
> VectorStore or the embedder directly.

### Phase 3 — Cross-cutting Glue

**A: bridge scanner → retriever**

- [ ] `scanners/port_risk.py` — for each open port on a `Device`, call
      `retriever.lookup_port_risk` + LLM reasoning, return `list[RiskFinding]`

**B: expose everything to LangChain**

- [x] `agent/tools.py.build_tools(retriever)` — six `StructuredTool`s with
      explicit Pydantic arg schemas, JSON-string observations; `lookup_cve` uses
      the passed retriever, `check_open_ports_risk` delegates to A's port_risk
      (`3284fc5`)
- [x] First draft of `config/prompts.py` — `AGENT_SYSTEM_PROMPT` +
      `REPORT_GENERATION_PROMPT` + `QA_FOLLOWUP_PROMPT`; hybrid autonomy,
      anti-hallucination + five-dimension/severity rubric (`6a2b239`)

> 🔁 **SYNC 2**: First end-to-end "tool list" exists. Run a hand-crafted
> agent prompt against a mock LLM that selects each tool once — verifies
> all six tools wire up without raising.
>
> **B side ready.** `scripts/smoke_tools.py` (`0bb82a9`) automates this offline
> (fixtures for scanners/retriever): 5/6 tools PASS, `check_open_ports_risk`
> reports PENDING until A implements `scanners/port_risk.py`. Still to agree
> with A: (1) scanner signatures frozen, (2) port_risk timeline, (3) §7
> autonomous-vs-sequential, (4) whether tools should later return structured
> objects via `content_and_artifact`.

### Phase 4 — Agent Executor & Report

**A: UI shell (no live agent yet)**

- [ ] `ui/chat.py` — Streamlit chat skeleton (pre-scan CTA + post-scan history)
- [ ] `ui/report_view.py` — render a hand-crafted `ScanReport` fixture nicely
- [ ] `app.py` — bootstrap LLM + retriever + agent, mount chat

**B: agent runtime**

- [ ] `agent/core.py.SecurityAgent` — LangChain Tool-Calling executor + memory
- [x] `agent/reporter.py.assemble_report` + `grade_from_findings` —
      deterministic A–F grade (proposal §4.2 anchor) + Markdown summary,
      Pydantic-only, no LLM (`5731b65`)
- [ ] Iterate `AGENT_SYSTEM_PROMPT` / `REPORT_GENERATION_PROMPT` until the
      agent reliably calls tools in the planned order

### Phase 5 — End-to-end on a Real Network

Both members, working together:

- [ ] Run `streamlit run app.py` against the team's own home network
- [ ] Verify the full chain: UI click → autonomous tool calls → real `ScanReport`
- [ ] Capture failures: missed devices, hallucinated CVEs, prompt loops,
      latency, sudo issues — log and triage
- [ ] Fix the top 3 blockers from that triage

### Phase 6 — Testing, Polish, Demo

**A: testing & demo**

- [ ] `tests/test_scanners.py` — fixture-driven tests (no real network calls)
- [ ] Demo script: 3 scenarios (clean network / risky IoT / vulnerable router)
- [ ] Screenshots for the final report

**B: prompt regression & report quality**

- [ ] Frozen "golden" scan inputs → check report grade is stable
- [ ] Q&A regression set: 5–10 representative follow-up questions
- [ ] Trim hallucinations: tighten prompts when the agent invents CVEs

---

## 5. Acceptance Criteria (what we demo)

1. From cold start, `streamlit run app.py` boots without errors.
2. Clicking **Start Scan** triggers the agent; the UI streams tool-call progress.
3. A `ScanReport` is produced with: overall A–F grade, per-device findings,
   five-dimension risk breakdown, prioritised remediation steps.
4. At least one **high-risk** finding cites a real CVE retrieved from the KB.
5. Three follow-up Q&A turns work, each grounded in the prior scan plus KB.

---

## 6. Risks & Mitigations

| Risk                                                    | Mitigation                                                                              |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Nmap `-O` needs sudo on macOS                           | Document `sudo` invocation; gate OS detection behind a flag and fall back gracefully    |
| NVD API rate limit (5 req / 30s without key)            | Use `NVD_API_KEY`; cache raw JSON under `data/knowledge_base/raw/nvd/`                  |
| Azure OpenAI quota or latency spikes during demo        | Pre-warm embedding cache; allow `--offline` mode that loads a cached `ScanReport`       |
| Router probe misidentifies vendor                       | Combine HTTP `Server` header + HTML title + OUI; fall back to "unknown" instead of guessing |
| LLM hallucinates CVE IDs not in the KB                  | System prompt rule: "Only cite CVE IDs returned by `lookup_cve`"; add a regression test |
| Two devs touch `models/` simultaneously                 | Treat `models/` as a contract — PR for any schema change, both review                   |

---

## 7. Open Questions (decide before Phase 3)

- Do we need a **device-type classifier** (camera / speaker / NAS) or is
  vendor + open ports enough for risk reasoning?
- Should the agent be **strictly sequential** (fixed tool order) or
  **autonomous** (LLM decides)? Autonomous is more impressive; sequential
  is more predictable for the demo.
- How do we handle **scan duration** in the UI — block, or background +
  polling? Nmap on `/24` with `-sV -O` can take minutes.
