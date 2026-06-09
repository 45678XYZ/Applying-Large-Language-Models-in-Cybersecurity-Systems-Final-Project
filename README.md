# LLM-Powered Home Network Security Auditor

An LLM-Agent-driven system that automatically audits the security posture
of a home Wi-Fi network — discovering devices, profiling their attack
surface, cross-referencing CVE / OWASP knowledge, and producing a graded
report plus a natural-language Q&A interface.

## Architecture Layers

```
┌────────────────────────────────────────────────────────────┐
│  ui/            Streamlit Chat UI (scan trigger + Q&A)     │
├────────────────────────────────────────────────────────────┤
│  agent/         LangChain Tool-Calling Agent               │
│                 ├─ core      Agent executor                │
│                 ├─ tools     LangChain Tool wrappers       │
│                 └─ reporter  Report assembly               │
├────────────────────────────────────────────────────────────┤
│  scanners/      Tool execution layer (Nmap / nmcli / HTTP) │
│                 network_info / wifi_security               │
│                 nmap_scanner / router_probe / port_risk    │
├────────────────────────────────────────────────────────────┤
│  rag/           Vector KB (ChromaDB + Azure Embeddings)    │
│                 vector_store / embeddings / retriever      │
│                 ingest/  NVD / OWASP / NIST loaders        │
└────────────────────────────────────────────────────────────┘

models/    Shared Pydantic schemas (Device / CVE / Report …)
config/    Settings & system prompts
utils/     Shared helpers (logger, OUI lookup)
scripts/   One-shot scripts (build KB, fetch NVD, run scan, regression)
tests/     Unit tests
data/      Raw KB documents + persisted vector store
```

## Primary Data Flow

1. **UI → Agent**: user triggers "Start Scan".
2. **Agent → Scanners**: sequentially invokes `get_network_info` →
   `get_wifi_security` → `scan_network` → `check_router_info`.
3. **Scanners → Models**: raw output is normalised into `Device` /
   `WiFiInfo` / `RouterInfo` Pydantic objects.
4. **Agent → RAG**: per device / service, calls `lookup_cve` and
   `check_open_ports_risk` against the vector KB.
5. **Agent → Reporter**: synthesises everything into a `ScanReport`.
6. **UI ← Report**: report is rendered, then the UI enters Q&A mode.

## Prerequisites

- **Python 3.12**, managed with [uv](https://docs.astral.sh/uv/) (the virtualenv lives in `.venv/`).
- **Nmap** — a *system* binary that the `python-nmap` package shells out to
  (it is **not** a pip dependency):
  - macOS: `brew install nmap`
  - Debian / Ubuntu: `sudo apt install nmap`
- **Wi-Fi tooling** used by `get_wifi_security`: `nmcli` (NetworkManager) on Linux;
  built-in utilities on macOS / Windows.
- **Azure OpenAI** credentials (a chat deployment + `text-embedding-3-small`) in `.env`.

> OS detection (`nmap -O`) needs `sudo`; it is **off by default**, so a normal
> scan runs without elevated privileges. Launch with `sudo` (e.g.
> `sudo .venv/bin/python -m streamlit run app.py`) and the agent auto-enables
> `-O` — root also lets nmap use ARP host discovery, so it finds more devices.

## Quick Start

### 1. Set up the environment

```bash
uv venv && uv pip install -r requirements.txt   # create .venv and install deps
cp .env.example .env                            # fill in Azure OpenAI credentials
.venv/bin/python scripts/build_kb.py            # build the RAG knowledge base
```

### 2. Run a scan from the CLI

```bash
.venv/bin/python scripts/run_scan.py                          # scan + interactive Q&A
.venv/bin/python scripts/run_scan.py --offline report.json    # demo from a cached report
```

### 3. Launch the Streamlit UI

Graded report + streaming Q&A.

```bash
streamlit run app.py                              # normal launch (no OS detection)
sudo .venv/bin/python -m streamlit run app.py     # run as root → auto OS detection + ARP discovery (finds more devices)
```

### 4. Regression checks

```bash
.venv/bin/python scripts/golden_scan.py     # deterministic grading/report (no LLM, no network)
.venv/bin/python scripts/prompt_probes.py   # synthesis grounding probes (needs Azure creds + KB)
.venv/bin/python scripts/qa_regression.py   # grounded-answer checks (needs Azure creds + KB)
```
