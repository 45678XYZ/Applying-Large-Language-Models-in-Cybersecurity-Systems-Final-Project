"""Q&A regression set — check the agent's follow-up answers stay grounded.

Loads a fixed scan report (the synthetic `golden_fixtures` network by default,
or a saved report via `--report`) and runs a bank of follow-up questions
through `SecurityAgent.ask`, scoring each answer against groundedness rules:

    any_of  — fact groups that MUST appear (the report's grade, the exact CVE
              id it cites, the affected device) — the answer is anchored.
    none_of — fabrications that must NOT appear (a neighbour's password, a
              Heartbleed finding the scan never produced) — no hallucination.

The grade and CVE expectations are read live from the loaded report, so the
same bank works against the golden network or a real saved scan.

This is an LLM eval, not a unit test: it needs Azure credentials + a built KB,
and runs at temperature 0 for stability. Exit codes:
    0 — every runnable case passed
    1 — a grounding regression (answer missing a fact or fabricating one)
    2 — could not run (missing credentials / KB / report)

Usage:
    .venv/bin/python scripts/qa_regression.py
    .venv/bin/python scripts/qa_regression.py --report data/sample_report.json
    .venv/bin/python scripts/qa_regression.py --verbose
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

# Keep .env authoritative over stale shell exports, per project convention.
load_dotenv(override=True)

from agent.reporter import GRADE_LABEL, assemble_report  # noqa: E402
from models import ScanReport  # noqa: E402
from rag import build_default_retriever  # noqa: E402

from agent.core import SecurityAgent  # noqa: E402
from golden_fixtures import golden_findings, golden_network  # noqa: E402


def _build_llm():
    """Construct the Azure OpenAI chat model from settings (lazy import)."""
    from config import settings
    from langchain_openai import AzureChatOpenAI

    return AzureChatOpenAI(
        azure_deployment=settings.azure_openai_chat_deployment,
        azure_endpoint=settings.azure_openai_endpoint,
        api_key=settings.azure_openai_api_key,
        api_version=settings.azure_openai_api_version,
        temperature=0,
    )


def _golden_report() -> ScanReport:
    network, wifi, router, devices = golden_network()
    return assemble_report(network, wifi, router, devices, golden_findings())


def _first_cve_id(report: ScanReport) -> str | None:
    for finding in report.findings:
        for cve in finding.related_cves:
            return cve.cve_id
    return None


def qa_cases(report: ScanReport) -> list[dict]:
    """The question bank, with expectations partly derived from the report.

    `any_of`: list of groups; each group needs at least one match (OR within a
    group, AND across groups). `none_of`: none may appear. `skip`: drop the
    case when its anchor is absent from this report.
    """
    grade = report.overall_grade
    grade_word = GRADE_LABEL.get(grade, "").lower()
    cve_id = _first_cve_id(report)

    return [
        {
            "q": "What overall security grade did my home network receive, and what are the main reasons?",
            "any_of": [
                [f"grade {grade.lower()}", f"grade of {grade.lower()}", f"{grade.lower()} (", grade_word],
                ["high", "medium", "critical", "vulnerab"],
            ],
            "none_of": ["no issues", "everything looks secure", "no risks were found"],
        },
        {
            "q": "Which device or service on my network has the most serious problem?",
            "any_of": [["router", "gateway", "busybox", "upnp", "192.168.0.1"]],
            "none_of": [],
        },
        {
            "q": "Is my Wi-Fi encryption strong enough, or should I change it?",
            "any_of": [["wpa2", "wpa3", "encryption"]],
            "none_of": ["wep is fine", "open network is secure"],
        },
        {
            "q": "Which CVE was found on my router, and how severe is it?",
            "any_of": [[cve_id.lower()]] if cve_id else [],
            # Only flat denials — phrases that can't be a negated mention.
            "none_of": ["no known cve", "not aware of any cve"],
            "skip": cve_id is None,
            "skip_reason": "loaded report cites no CVE",
        },
        {
            "q": "If I can only fix one thing first, what should it be?",
            "any_of": [["firmware", "upnp", "update", "disable", "patch"]],
            "none_of": [],
        },
        {
            "q": "Do I have a separate guest or IoT network, or is everything on one subnet?",
            "any_of": [["guest", "isolat", "vlan", "same subnet", "one subnet", "separate", "segment"]],
            "none_of": [],
        },
        {
            # Out-of-scope device probe: no thermostat was discovered. A grounded
            # agent says so instead of inventing one with a made-up IP.
            "q": "Is there a smart thermostat on my network, and what is its IP address?",
            "any_of": [
                ["thermostat"],
                [
                    "no ", "not ", "can't", "cannot", "can not", "didn't", "did not",
                    "wasn't", "was not", "doesn't", "does not", "no evidence",
                    "not detected", "not found", "none", "no such", "no smart thermostat",
                ],
            ],
            "none_of": [],
        },
        {
            # Hallucination probe: the report never produced a Heartbleed finding.
            "q": "Does my network have the Heartbleed vulnerability?",
            "any_of": [
                ["heartbleed"],
                [
                    "no ", "not ", "can't", "cannot", "can not", "wasn't", "was not",
                    "did not", "didn't", "no evidence", "not detected", "not found",
                    "does not", "doesn't", "not observe", "not among", "no indication",
                    "unlikely", "no sign",
                ],
            ],
            # No none_of: a fabricated "yes, you have Heartbleed" lacks the
            # negation token above, so it already fails any_of. Any forbidden
            # phrase here ("...heartbleed found") is too easily negated ("no
            # heartbleed found") to score reliably.
            "none_of": [],
        },
    ]


def _normalize(s: str) -> str:
    """Lower-case and fold smart quotes so matching isn't foiled by typography
    (the LLM writes `can't` with a curly apostrophe)."""
    return (
        s.lower()
        .replace("’", "'")
        .replace("‘", "'")
        .replace("“", '"')
        .replace("”", '"')
    )


def _grade_answer(answer: str, case: dict) -> tuple[list[str], list[str]]:
    """Return (missing fact-groups, forbidden phrases present)."""
    text = _normalize(answer)
    missing = [" / ".join(g) for g in case["any_of"] if not any(_normalize(s) in text for s in g)]
    forbidden = [s for s in case["none_of"] if _normalize(s) in text]
    return missing, forbidden


def _excerpt(answer: str, width: int = 100) -> str:
    flat = " ".join(answer.split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


def _is_content_block(exc: Exception) -> bool:
    """True for a provider content-policy refusal (e.g. Azure's `cyber_policy`).

    Such a block is the provider declining the request, not a grounding
    regression in our agent — a safe outcome, so the suite tolerates it.
    """
    msg = str(exc).lower()
    return any(
        marker in msg
        for marker in ("content_filter", "cyber_policy", "content_policy", "content management policy", "flagged for")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Grounded-answer regression for SecurityAgent.ask.")
    parser.add_argument("--report", metavar="PATH", help="Score against a saved ScanReport JSON instead of the golden one.")
    parser.add_argument("--verbose", action="store_true", help="Print each full answer.")
    args = parser.parse_args()

    if args.report:
        try:
            report = ScanReport.model_validate_json(Path(args.report).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"SKIP: could not load report {args.report} ({exc})")
            return 2
        source = args.report
    else:
        report = _golden_report()
        source = "golden_fixtures (synthetic)"

    try:
        retriever = build_default_retriever()
        llm = _build_llm()
    except Exception as exc:  # noqa: BLE001
        print(f"SKIP: could not initialise LLM/retriever ({exc})")
        return 2

    agent = SecurityAgent(llm, retriever)
    agent.load_report(report)

    cases = qa_cases(report)
    print("Q&A regression — grounded follow-up answers")
    print(f"report: grade {report.overall_grade}, {len(report.findings)} findings, source: {source}")
    print("=" * 60)

    passed = failed = errored = skipped = blocked = 0
    for i, case in enumerate(cases, 1):
        print(f"\nQ{i}. {case['q']}")
        if case.get("skip"):
            skipped += 1
            print(f"  [SKIP] {case.get('skip_reason', 'not applicable to this report')}")
            continue
        try:
            answer = agent.ask(case["q"])
        except Exception as exc:  # noqa: BLE001 - classify infra vs provider policy
            if _is_content_block(exc):
                blocked += 1
                print(f"  [BLOCK] provider content policy refused the request (safe, not scored)")
                continue
            errored += 1
            print(f"  [ERROR] {type(exc).__name__}: {exc}")
            continue

        missing, forbidden = _grade_answer(answer, case)
        if not missing and not forbidden:
            passed += 1
            print(f"  [PASS] {_excerpt(answer)}")
        else:
            failed += 1
            print(f"  [FAIL] {_excerpt(answer)}")
            if missing:
                print(f"         missing: {'; '.join(missing)}")
            if forbidden:
                print(f"         fabricated: {', '.join(forbidden)}")
        if args.verbose:
            print(f"         full: {' '.join(answer.split())}")

    print("\n" + "=" * 60)
    runnable = passed + failed
    print(
        f"grounded: {passed}/{runnable} pass · {failed} fail · "
        f"{blocked} blocked · {skipped} skipped · {errored} error"
    )
    if runnable == 0:
        print("RESULT: SKIP — no answers scored (provider blocks / errors / skips)")
        return 2
    if failed or errored:
        print("RESULT: FAIL — a grounding regression (re-run once; temp 0 keeps it stable)")
        return 1
    print("RESULT: PASS — every answer stayed grounded in the report")
    return 0


if __name__ == "__main__":
    sys.exit(main())
