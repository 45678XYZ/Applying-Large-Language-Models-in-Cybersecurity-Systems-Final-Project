"""Run a full home-network security scan end-to-end from the command line.

Wires Azure OpenAI (chat) + the RAG retriever + `SecurityAgent`, runs the
sequential scan pipeline against the local network, streams progress, prints
the graded report, then drops into an interactive Q&A loop.

This doubles as the B-side reference for `app.py` (A's Streamlit bootstrap):
it shows exactly how to construct `SecurityAgent(llm, retriever, on_event=...)`.

Usage:
    .venv/bin/python scripts/run_scan.py                    # live scan + Q&A
    .venv/bin/python scripts/run_scan.py --ask "..."        # scan, one question, exit
    .venv/bin/python scripts/run_scan.py --save report.json # save the ScanReport
    .venv/bin/python scripts/run_scan.py --offline report.json  # load cache, skip scan

Requires a populated KB (`scripts/build_kb.py`) and Azure credentials in `.env`.
Scanning runs nmap; OS detection is off unless run as root — under `sudo` the
agent auto-enables `nmap -O` (and ARP host discovery, which finds more hosts).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

# Keep .env authoritative over stale shell exports, per project convention.
load_dotenv(override=True)

from config import settings  # noqa: E402
from models import ScanReport  # noqa: E402
from rag import build_default_retriever  # noqa: E402

from agent.core import SecurityAgent  # noqa: E402


def _build_llm():
    """Construct the Azure OpenAI chat model from settings (lazy import)."""
    from langchain_openai import AzureChatOpenAI

    return AzureChatOpenAI(
        azure_deployment=settings.azure_openai_chat_deployment,
        azure_endpoint=settings.azure_openai_endpoint,
        api_key=settings.azure_openai_api_key,
        api_version=settings.azure_openai_api_version,
        temperature=0,
    )


def _on_event(message: str) -> None:
    print(f"  ▸ {message}")


def _print_streamed_answer(agent: SecurityAgent, question: str) -> None:
    """Print the answer token-by-token as it arrives, matching the UI's feel."""
    for chunk in agent.ask_stream(question):
        print(chunk, end="", flush=True)
    print()


def _qa_loop(agent: SecurityAgent, single: str | None) -> None:
    if single is not None:
        print(f"\nQ: {single}")
        print("A: ", end="", flush=True)
        _print_streamed_answer(agent, single)
        return
    print("\nQ&A mode — ask about the scan (blank line or 'exit' to quit).")
    while True:
        try:
            question = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not question or question.lower() in {"exit", "quit"}:
            break
        _print_streamed_answer(agent, question)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a home-network security scan.")
    parser.add_argument("--ask", metavar="Q", help="Ask one question after scanning, then exit.")
    parser.add_argument("--save", metavar="PATH", help="Save the ScanReport JSON to PATH.")
    parser.add_argument(
        "--offline",
        metavar="PATH",
        help="Load a cached ScanReport JSON and skip scanning (Q&A only).",
    )
    args = parser.parse_args()

    retriever = build_default_retriever()
    agent = SecurityAgent(_build_llm(), retriever, on_event=_on_event)

    if args.offline:
        report = ScanReport.model_validate_json(Path(args.offline).read_text(encoding="utf-8"))
        agent.load_report(report)
        print(f"Loaded cached report (grade {report.overall_grade}) from {args.offline}.")
    else:
        print("Starting scan…")
        report = agent.run_full_scan()
        if args.save:
            Path(args.save).write_text(report.model_dump_json(indent=2), encoding="utf-8")
            print(f"\nSaved report to {args.save}.")

    print("\n" + "=" * 60)
    print(report.summary_markdown)
    print("=" * 60)

    _qa_loop(agent, args.ask)
    return 0


if __name__ == "__main__":
    sys.exit(main())
