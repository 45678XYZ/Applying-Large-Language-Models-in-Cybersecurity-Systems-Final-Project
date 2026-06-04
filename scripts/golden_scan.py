"""Golden-scan regression — pin the deterministic report pipeline.

Runs the fixed `golden_fixtures` network through `reporter.assemble_report`
(no LLM, no network) and checks the parts that MUST be reproducible:

    * the overall A-F grade and its severity-count header,
    * findings sorted worst-first,
    * the CVE id rendered in the Markdown,
    * all five risk dimensions rendered, and
    * remediation steps deduplicated and ordered by severity.

It also replays `grade_scenarios()` to lock every branch of the grading
rubric. Any change to `agent/reporter.py` that shifts a grade or drops a
section trips this. Exit 0 when everything matches, 1 on a regression.

Usage:
    .venv/bin/python scripts/golden_scan.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.reporter import (  # noqa: E402
    DIMENSION_LABEL,
    SEVERITY_ORDER,
    assemble_report,
    grade_from_findings,
)
from golden_fixtures import (  # noqa: E402
    GOLDEN_CVE_ID,
    golden_findings,
    golden_network,
    grade_scenarios,
)

Check = tuple[str, str, str]  # (status, label, detail)


def _expect(ok: bool, label: str, detail: str = "") -> Check:
    return ("PASS" if ok else "FAIL", label, detail)


def _severity_sequence_ok(findings) -> bool:
    """True if findings are ordered worst-first (non-decreasing rank)."""
    ranks = [SEVERITY_ORDER.get(f.severity, 99) for f in findings]
    return ranks == sorted(ranks)


def _report_checks() -> list[Check]:
    """Assemble the golden report once and assert its deterministic shape."""
    network, wifi, router, devices = golden_network()
    report = assemble_report(network, wifi, router, devices, golden_findings())
    md = report.summary_markdown
    high = sum(f.severity == "high" for f in report.findings)
    medium = sum(f.severity == "medium" for f in report.findings)
    low = sum(f.severity == "low" for f in report.findings)

    checks = [
        _expect(report.overall_grade == "C", "overall grade is C", f"got {report.overall_grade}"),
        _expect((high, medium, low) == (2, 3, 1), "severity mix 2H/3M/1L", f"got {high}H/{medium}M/{low}L"),
        _expect(_severity_sequence_ok(report.findings), "findings sorted worst-first"),
        _expect("High: 2 · Medium: 3 · Low: 1" in md, "header counts rendered"),
        _expect(f"Devices discovered:** {len(report.devices)}" in md, "device count in header"),
        _expect(GOLDEN_CVE_ID in md, "CVE id cited in Markdown", GOLDEN_CVE_ID),
        _expect("no issues found" not in md, "all five dimensions report a finding"),
    ]
    # Every dimension label must appear in the breakdown section.
    for label in DIMENSION_LABEL.values():
        checks.append(_expect(label in md, f"dimension rendered: {label}"))

    # Remediation: 6 distinct recommendations → 6 deduplicated, severity-ordered steps.
    remediation = md.split("## Prioritised Remediation", 1)[-1]
    step_lines = [ln for ln in remediation.splitlines() if ln[:2].strip().rstrip(".").isdigit()]
    checks.append(_expect(len(step_lines) == 6, "6 remediation steps (deduplicated)", f"got {len(step_lines)}"))
    checks.append(
        _expect(
            "Update the router firmware" in remediation
            and remediation.index("Update the router firmware") < remediation.index("Restrict SSH"),
            "remediation ordered high → low",
        )
    )
    return checks


def _rubric_checks() -> list[Check]:
    """Replay the boundary scenarios against the grading rubric."""
    checks = []
    for name, findings, expected in grade_scenarios():
        got = grade_from_findings(findings)
        checks.append(_expect(got == expected, f"grade {expected}: {name}", f"got {got}"))
    return checks


def main() -> int:
    print("Golden-scan regression — deterministic report pipeline\n" + "=" * 54)

    sections = [("report assembly", _report_checks()), ("grading rubric", _rubric_checks())]
    failed = 0
    total = 0
    for title, checks in sections:
        print(f"\n[{title}]")
        for status, label, detail in checks:
            total += 1
            failed += status == "FAIL"
            tail = f"  ({detail})" if detail and status == "FAIL" else ""
            print(f"  [{status}]".ljust(10) + label + tail)

    print("\n" + "=" * 54)
    print(f"checks: {total - failed}/{total} pass · {failed} fail")
    if failed:
        print("RESULT: FAIL — deterministic output drifted from the golden baseline")
        return 1
    print("RESULT: PASS — golden scan reproduced exactly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
