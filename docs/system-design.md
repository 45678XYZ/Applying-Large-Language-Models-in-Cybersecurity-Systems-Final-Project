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

## 1.5. Status Snapshot (updated 2026-06-06)

```
Phase 0 — Bootstrap                          ✅ DONE
Phase 1 — Foundation
  ├─ A: scanners (5 tasks)                  █████  DONE
  └─ B: RAG knowledge base (6 tasks)        █████  DONE
Phase 2 — Retrieval & Tooling Layer
  ├─ A: scanner enrichment (2 tasks)        ██     DONE
  └─ B: retriever API (4 tasks)             ████   DONE  ← SYNC 1 locked
Phase 3 — Cross-cutting Glue                 DONE
  ├─ A: port_risk.py (1 task)               █      DONE
  └─ B: tools.py + prompts draft (2)        ██     DONE  ← SYNC 2 ready (B side)
Phase 4 — Agent Executor & Report            DONE
  ├─ A: UI shell (3 tasks)                  ███    DONE
  └─ B: core / reporter / prompt-iter (3)   ███    DONE
Phase 5 — End-to-end on a Real Network       live re-run grade C; UI cold-boot verified; screenshots pending
Phase 6 — Testing, Polish, Demo              regression suites green (A+B); acceptance #1–#5 met
```

**KB built end-to-end**: 5,355 CVE chunks + 200 KB chunks; semantic +
metadata-filtered retrieval verified on both collections.

**SYNC 1 contract** (Retriever API, frozen for A and B's downstream use):
- `lookup_cve(product, version=None, k=5, min_cvss=None) -> list[CVE]`
- `lookup_port_risk(port, service=None, k=5) -> list[dict]`  (text/source/filename/distance)
- `search(query, k=5) -> list[dict]`  (same shape as lookup_port_risk)
- Factory: `rag.build_default_retriever()`

**§7 decided (2026-06-03).** Agent orchestration is **strictly sequential**
(fixed Python pipeline in `core.py`, not LLM-chosen); no device-type classifier
(LLM infers); UI **streams progress with fast-scan defaults** (pending A
sign-off on the `core.py` callback interface). The A–F grade stays
deterministic in `reporter.py`. `AGENT_SYSTEM_PROMPT` will be trimmed of its
tool-selection framing when `core.py` lands. See §7 for the full rationale.

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

- [x] `scanners/port_risk.py` — for each open port on a `Device`, call
      `retriever.lookup_port_risk` + LLM reasoning, return `list[RiskFinding]`

**A status:** DONE in `scanners/port_risk.py`; implemented retriever-backed `list[RiskFinding]` output with offline tests.

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
> (fixtures for scanners/retriever): `check_open_ports_risk` is now implemented
> by A's `scanners/port_risk.py`; rerun once dependencies are installed. Still to agree:
> (1) scanner signatures frozen, (2) the `core.py` progress-callback interface
> (§7 decided: sequential + streaming UI), (3) whether tools should later return
> structured objects via `content_and_artifact`.

### Phase 4 — Agent Executor & Report

**A: UI shell**

- [x] `ui/chat.py` — Streamlit chat skeleton (pre-scan CTA + post-scan history)
- [x] `ui/report_view.py` — render a hand-crafted `ScanReport` fixture nicely
- [x] `app.py` — bootstrap LLM + retriever + agent, mount chat

**B: agent runtime**

- [x] `agent/core.py.SecurityAgent` — sequential scan pipeline + progress
      callback + LLM finding synthesis (graceful-degrading) + grounded Q&A
      (`fc58c2b`); prompt reframed for the sequential design (`a4670e6`)
- [x] `agent/reporter.py.assemble_report` + `grade_from_findings` —
      deterministic A–F grade (proposal §4.2 anchor) + Markdown summary,
      Pydantic-only, no LLM (`5731b65`)
- [ ] Iterate `AGENT_SYSTEM_PROMPT` / `REPORT_GENERATION_PROMPT` against a live
      LLM until findings are clean (no hallucinated CVEs) and Q&A stays grounded

### Phase 5 — End-to-end on a Real Network

Both members, working together:

- [x] First end-to-end run via CLI (`scripts/run_scan.py`) against a real home
      network — full chain verified: nmap → KB retrieval → LLM synthesis →
      graded `ScanReport` → grounded Q&A (2026-06-04). `--offline` cache mode
      (the §6 fallback) also works.
- [ ] Re-run through `streamlit run app.py` against the live network and capture screenshots.
      Live pipeline re-run now lands at grade **C** (2 real-CVE highs) with Wi-Fi read
      as WPA2; `app.py` cold-boot verified headless via Streamlit `AppTest` (no
      exceptions, report renders) (2026-06-06). In-app screenshot capture is the
      only open item.
- [x] Capture failures — triage logged below.
- [x] Fix the top 3 blockers from that triage.

**Triage log — first run (2026-06-04):**

| # | Symptom | Owner | Action |
| - | ------- | ----- | ------ |
| 1 | Grade **F** is over-aggressive: `port_risk` marks every open gateway port (DNS/HTTP/HTTPS/UPnP) as `high` → 5 highs → F. A router serving http/https admin + DNS is normal. | A·B | **Done — live-confirmed F→C (2026-06-06).** A added LAN gateway baselines, but two gaps kept the live grade at F: the gateway device was never flagged `is_gateway`, so those baselines never applied (`abbddd6`), and a substring match (`rce` inside `source`/`resource`) re-escalated every port to high (`7d2cb86`). Both fixed + raw-KB dump removed from descriptions (`c2a8233`) → live re-run is now **C** with only the 2 real-CVE highs. |
| 2 | No CVE cited (misses acceptance #4): no sudo → no MAC → no vendor → `lookup_cve` had no product to query. | B | ✅ **Done & live-confirmed (2026-06-04).** `_gather_cves` now also queries each open port's `product`+`version` from `-sV` (`f026c41`). Re-run cited 10 real KB CVEs across 2 high findings (e.g. CVE-2024-54807 9.8, CVE-2018-5371 8.8) → acceptance #4 met. |
| 3 | Wi-Fi not detected on macOS (`airport` removed / needs Location permission) → only an info finding. | A·B | **Done — live-confirmed (2026-06-06).** `airport` is gone on macOS 14.4+ and `wdutil`/`networksetup` return a redacted SSID without Location Services, so detection still failed live. Switched to `system_profiler SPAirPortDataType -json` (`fceae45`): it reports Security/Channel/Signal even when only the SSID is redacted → live scan now reads **WPA2 / 5GHz**. Locale-safe (JSON keys) + unit-tested (`7c8708b`). |
| 4 | Router model/firmware not extracted from a generic BusyBox banner → exact-version CVE match not possible. | A/B | Known limit; low priority. **Mitigated (2026-06-09):** when the version can't be confirmed, a family-level CVE is surfaced as a hedged finding (capped below high, "verify firmware"), not a confident high — see §7. |

**A-side update (2026-06-05):** `port_risk` now uses LAN-specific baselines
for gateway DNS/HTTP/HTTPS/UPnP and no longer escalates every generic
"exposed" KB hit to high. macOS Wi-Fi detection now falls back to `wdutil info`
and dynamically discovered `networksetup` Wi-Fi interfaces. These fixes are
covered by fixture-driven scanner regressions.

**B follow-up (2026-06-06):** a live re-run showed those weren't yet sufficient
(grade still **F**, Wi-Fi still undetected). The completing fixes — flag the
gateway in `core.py`, drop the KB-keyword severity bump, and read Wi-Fi via
`system_profiler -json` — are detailed in triage #1/#3 above. The live re-run
now lands at **C** with Wi-Fi read as WPA2.

### Phase 6 — Testing, Polish, Demo

**A: testing & demo**

- [x] `tests/test_scanners.py` — fixture-driven tests (no real network calls);
      includes phase 5 regressions for gateway severity and macOS `wdutil`
      parsing. `python -m pytest tests\test_scanners.py --basetemp .pytest_tmp -p no:cacheprovider` → 10/10 pass.
- [x] Demo script: 3 scenarios (clean network / risky IoT / vulnerable router)
      in `scripts/demo_scenarios.py`, documented in `docs/demo-script.md`.
      `python scripts/demo_scenarios.py --export --out docs/demo-reports`
      writes deterministic Markdown/JSON reports for all three.
- [x] Screenshots for the final report: Streamlit sidebar now supports a
      selectable `Demo scenario`, so the final report can be captured from
      the exact UI for `Clean network`, `Risky IoT`, and `Vulnerable router`.
      Checklist and target paths are in `docs/demo-script.md`.

**B: prompt regression & report quality**

- [x] Frozen "golden" scan inputs → grade stable — `scripts/golden_scan.py`
      asserts the fixed `golden_fixtures` network reproduces grade **C** plus
      its rendered report, and pins every branch of the grading rubric
      (25 checks, no LLM / no network).
- [x] Q&A regression set — `scripts/qa_regression.py` runs 8 representative
      follow-up questions (grade, top risk, Wi-Fi, the cited CVE, fix-first,
      isolation, and two anti-hallucination probes), scoring each answer for
      grounding. Reads the grade/CVE anchors live from the report, so it runs
      against the golden network **or** any saved scan (`--report`). 8/8 pass.
- [x] Trim hallucinations — `scripts/prompt_probes.py` stress-tests the
      synthesis prompts with crafted CVE contexts (empty / relevant /
      mismatched / unconfirmed-version / missing). Grounding already held, so the
      first pass only anchored borderline severities in `config/prompts.py`
      (admin-panel-on-LAN, missing data) for a stable grade. A later probe
      (2026-06-09) added **version confidence**: a CVE that matches only the
      product family / unknown version is now capped below high and flagged
      "verify firmware", not asserted as exploitable. **14/14 invariants hold.**

> Both share `scripts/golden_fixtures.py` — one hand-authored home LAN whose
> graded output is deterministic (unlike a live nmap scan), which is what makes
> it usable as a regression baseline.
>
> 📄 Captured run transcripts (golden 25/25 · probes 14/14 · Q&A 8/8) and the
> convergence before/after are recorded in
> [`docs/phase6-regression.md`](phase6-regression.md).

---

## 5. Acceptance Criteria (what we demo)

1. From cold start, `streamlit run app.py` boots without errors.
2. Clicking **Start Scan** triggers the agent; the UI streams tool-call progress.
3. A `ScanReport` is produced with: overall A–F grade, per-device findings,
   five-dimension risk breakdown, prioritised remediation steps.
4. At least one **high-risk** finding cites a real CVE retrieved from the KB.
5. Three follow-up Q&A turns work, each grounded in the prior scan plus KB.

**Status (2026-06-06): all five met.** #1 verified headless via Streamlit
`AppTest` (cold boot, no exceptions, report renders); #2 streams through the
`on_event` callback; #3 and #4 confirmed on the live grade-**C** run (2 real-CVE
highs in a five-dimension graded report); #5 covered by `qa_regression.py`
(8/8 grounded). Live-network UI screenshots are the only remaining demo to-do.

---

## 6. Risks & Mitigations

| Risk                                                    | Mitigation                                                                              |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Nmap `-O` needs sudo on macOS                           | OS detection auto-gated on `os.geteuid()==0` (off without sudo, on under root); `_safe` degrades the scan if `-O` ever fails |
| NVD API rate limit (5 req / 30s without key)            | Use `NVD_API_KEY`; cache raw JSON under `data/knowledge_base/raw/nvd/`                  |
| Azure OpenAI quota or latency spikes during demo        | Pre-warm embedding cache; allow `--offline` mode that loads a cached `ScanReport`       |
| Router probe misidentifies vendor                       | Combine HTTP `Server` header + HTML title + OUI; fall back to "unknown" instead of guessing |
| LLM hallucinates CVE IDs not in the KB                  | System prompt rule: "Only cite CVE IDs returned by `lookup_cve`"; add a regression test |
| Two devs touch `models/` simultaneously                 | Treat `models/` as a contract — PR for any schema change, both review                   |

---

## 7. Decisions (resolved 2026-06-03)

- **Device-type classifier — NO.** Use vendor + open ports + OS and let the
  LLM infer device type (camera / NAS / …) during reasoning. `Device.device_type`
  may be filled opportunistically by a simple heuristic later; not a blocker.
- **Agent orchestration — STRICTLY SEQUENTIAL.** `agent/core.py` drives the
  scan as a fixed Python pipeline (`network → wifi → scan → router →
  lookup_cve per device → check_open_ports_risk → report`); order is guaranteed
  in code, not chosen by the LLM. The LLM is used only to (a) reason over the
  collected data into `RiskFinding`s and (b) answer Q&A. Chosen for demo
  predictability over the "autonomous agent" showcase. **Implication:**
  `AGENT_SYSTEM_PROMPT` drops the "decide which tool to call next / recommended
  workflow" framing (orchestration moved to code); role, grounding,
  anti-hallucination, and five-dimension/severity rules stay.
- **Scan duration in UI — STREAM PROGRESS + FAST DEFAULTS** (pending A sign-off).
  `core.py` exposes a callback hook so `ui/` can render tool-call progress
  step-by-step (`st.status`). Defaults: top-100 ports, OS detection off unless
  the app is run as root — `core.py` auto-enables `nmap -O` when
  `os.geteuid()==0` (root also unlocks ARP host discovery, which finds more
  hosts), so a normal run stays sudo-free; optionally narrow the host range;
  keep the `--offline` cached `ScanReport` as a demo fallback. **SYNC point:**
  agree the `core.py` callback interface with A before the UI wires to it.
- **CVE severity needs version confidence — CAP FAMILY-ONLY MATCHES (2026-06-09).**
  `lookup_cve` matches by product/service name (semantic), not CPE version range,
  so a retrieved CVE can belong to the same family without affecting the exact
  firmware here. The synthesis prompt now marks a CVE-backed finding **high only
  when the scanned version is confirmed in the CVE's affected range**; a
  family-only / unknown-version match is capped at medium (low if CVSS < 7.0) and
  worded "possible — verify firmware version". Locked in by
  `prompt_probes._probe_unconfirmed_version_cve`. Trade-off: fewer false-high CVE
  findings on live home scans, at the cost of not asserting exploitability we
  cannot confirm — chosen for honesty over alarm.
