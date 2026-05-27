# LLM-Powered Home Network Security Auditor

An LLM-Agent-driven system that automatically audits the security posture
of a home Wi-Fi network — discovering devices, profiling their attack
surface, cross-referencing CVE / OWASP knowledge, and producing a graded
report plus a natural-language Q&A interface.

## Architecture Layers

```
┌─────────────────────────────────────────────────────────┐
│  ui/            Streamlit Chat UI (scan trigger + Q&A)   │
├─────────────────────────────────────────────────────────┤
│  agent/         LangChain Tool-Calling Agent             │
│                 ├─ core      Agent executor              │
│                 ├─ tools     LangChain Tool wrappers     │
│                 └─ reporter  Report assembly             │
├─────────────────────────────────────────────────────────┤
│  scanners/      Tool execution layer (Nmap / nmcli / HTTP)│
│                 network_info / wifi_security             │
│                 nmap_scanner / router_probe / port_risk  │
├─────────────────────────────────────────────────────────┤
│  rag/           Vector KB (ChromaDB + Azure Embeddings)  │
│                 vector_store / embeddings / retriever    │
│                 ingest/  NVD / OWASP / CIS loaders       │
└─────────────────────────────────────────────────────────┘

models/    Shared Pydantic schemas (Device / CVE / Report …)
config/    Settings & system prompts
utils/     Shared helpers (logger, OUI lookup)
scripts/   One-shot scripts (build KB, fetch NVD)
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

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env             # fill in Azure OpenAI credentials
python scripts/build_kb.py       # build the RAG knowledge base
streamlit run app.py
```
