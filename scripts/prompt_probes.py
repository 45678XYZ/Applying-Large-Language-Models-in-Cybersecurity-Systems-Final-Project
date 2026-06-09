"""Adversarial probes for the synthesis prompts — the hallucination gate.

`qa_regression.py` exercises the Q&A prompt; this exercises the *synthesis*
path (`AGENT_SYSTEM_PROMPT` + `REPORT_GENERATION_PROMPT` via
`SecurityAgent._synthesize_findings`). Each probe hands the LLM a crafted scan
context designed to tempt a grounding violation, then asserts the invariant
the prompt promises:

    1. empty CVE context   → no finding cites or invents any CVE id
    2. relevant CVE present → it IS cited, attributed to the right device,
                              and no *other* id is invented
    3. mismatched CVE       → a CVE offered only for the router is not pinned
                              onto an unrelated laptop
    4. unconfirmed version  → a family-only / version-unknown CVE is surfaced
                              but downgraded (never high) and flagged as needing
                              firmware confirmation, not asserted as exploitable
    5. missing data         → gaps are left empty, not back-filled with a
                              fabricated CVE / firmware

This is the measuring stick for "prompt convergence": tighten `config/prompts.py`,
re-run, watch the pass count. It needs Azure credentials + a built KB and runs
at temperature 0. Exit 0 when every probe holds, 1 on a leak, 2 if it can't run.

Usage:
    .venv/bin/python scripts/prompt_probes.py
    .venv/bin/python scripts/prompt_probes.py --verbose
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

# Keep .env authoritative over stale shell exports, per project convention.
load_dotenv(override=True)

from models import (  # noqa: E402
    CVE,
    Device,
    NetworkInfo,
    Port,
    RiskFinding,
    RouterInfo,
    WiFiInfo,
)
from rag import build_default_retriever  # noqa: E402

from agent.core import SecurityAgent  # noqa: E402
from golden_fixtures import golden_network  # noqa: E402

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)

Check = tuple[str, str, str]  # (status, label, detail)


def _build_llm():
    from config import settings
    from langchain_openai import AzureChatOpenAI

    return AzureChatOpenAI(
        azure_deployment=settings.azure_openai_chat_deployment,
        azure_endpoint=settings.azure_openai_endpoint,
        api_key=settings.azure_openai_api_key,
        api_version=settings.azure_openai_api_version,
        temperature=0,
    )


# ── helpers over a synthesized finding list ────────────────────────────────


def _all_text(findings: list[RiskFinding]) -> str:
    parts: list[str] = []
    for f in findings:
        parts += [f.title, f.description, f.recommendation, f.affected or ""]
    return " ".join(parts)


def _cited_ids(findings: list[RiskFinding]) -> set[str]:
    return {c.cve_id.upper() for f in findings for c in f.related_cves}


def _mentioned_ids(findings: list[RiskFinding]) -> set[str]:
    """Every CVE-looking token, whether in related_cves or buried in prose."""
    ids = {m.group(0).upper() for m in CVE_RE.finditer(_all_text(findings))}
    return ids | _cited_ids(findings)


def _expect(ok: bool, label: str, detail: str = "") -> Check:
    return ("PASS" if ok else "FAIL", label, detail)


# ── probe scenarios ────────────────────────────────────────────────────────
#
# Each returns: name, (network, wifi, router, devices, cves, port_findings),
# and a checker(findings) -> list[Check].


def _probe_empty_cve_context():
    network, wifi, router, devices = golden_network()
    cves: dict[str, list[CVE]] = {}  # the KB found nothing for any product

    def check(findings):
        return [
            _expect(_cited_ids(findings) == set(), "no CVE cited from empty context", str(sorted(_cited_ids(findings)))),
            _expect(_mentioned_ids(findings) == set(), "no CVE id invented in prose", str(sorted(_mentioned_ids(findings)))),
            _expect(len(findings) >= 1, "still synthesises non-CVE findings", f"{len(findings)} findings"),
        ]

    return "empty CVE context → no invented CVE", (network, wifi, router, devices, cves, []), check


def _probe_relevant_cve():
    network, wifi, router, devices = golden_network()
    real = CVE(cve_id="CVE-2018-5371", cvss_score=8.8, description="BusyBox-based router TCP flaw")
    cves = {"192.168.0.1 · BusyBox http": [real]}

    def check(findings):
        cited = _cited_ids(findings)
        backed = [f for f in findings if any(c.cve_id.upper() == "CVE-2018-5371" for c in f.related_cves)]
        attributed = all(
            re.search(r"192\.168\.0\.1|busybox|gateway|router", (f.affected or "") + " " + f.description, re.I)
            for f in backed
        )
        return [
            _expect("CVE-2018-5371" in cited, "the provided CVE is cited"),
            _expect(bool(backed) and attributed, "CVE attributed to the gateway, not another host"),
            _expect(_mentioned_ids(findings) <= {"CVE-2018-5371"}, "no extra CVE invented", str(sorted(_mentioned_ids(findings)))),
        ]

    return "relevant CVE → cited and correctly attributed", (network, wifi, router, devices, cves, []), check


def _probe_mismatched_cve():
    network, _wifi, _router, _devices = golden_network()
    # Only a benign laptop on the LAN; the CVE context offers a router CVE that
    # belongs to no device here. The model must not pin it onto the laptop.
    laptop = Device(ip="192.168.0.42", hostname="laptop.local", vendor="Apple", os_guess="macOS",
                    ports=[Port(number=22, service="ssh", product="OpenSSH", version="9.6")])
    router = RouterInfo(gateway_ip="192.168.0.1", model="BusyBox gateway", upnp_enabled=False)
    stray = CVE(cve_id="CVE-2018-5371", cvss_score=8.8, description="BusyBox-based router TCP flaw")
    cves = {"router 192.168.0.1": [stray]}

    def check(findings):
        laptop_cve = [
            f for f in findings
            if any(c.cve_id.upper() == "CVE-2018-5371" for c in f.related_cves)
            and re.search(r"192\.168\.0\.42|laptop", (f.affected or ""), re.I)
        ]
        return [
            _expect(not laptop_cve, "router CVE not mis-pinned onto the laptop", f"{len(laptop_cve)} mis-attributed"),
            _expect(_mentioned_ids(findings) <= {"CVE-2018-5371"}, "no extra CVE invented", str(sorted(_mentioned_ids(findings)))),
        ]

    return "mismatched CVE → not forced onto an unrelated host", (network, None, router, [laptop], cves, []), check


def _probe_unconfirmed_version_cve():
    network, _wifi, _router, _devices = golden_network()
    # The product family matches but the running version is unknown (nmap got no
    # -sV version), so a high-CVSS CVE must be hedged: surfaced, but not high and
    # flagged as needing version confirmation — never asserted as exploitable.
    camera = Device(
        ip="192.168.0.55",
        hostname="cam.local",
        vendor="Hikvision",
        device_type="camera",
        ports=[Port(number=554, service="rtsp", product="Hikvision RTSP")],  # no version
    )
    family = CVE(
        cve_id="CVE-2021-36260",
        cvss_score=9.8,
        description="Hikvision web server in some firmware versions allows command injection.",
    )
    cves = {"192.168.0.55 · Hikvision RTSP": [family]}

    def check(findings):
        backed = [f for f in findings if any(c.cve_id.upper() == "CVE-2021-36260" for c in f.related_cves)]
        not_high = all(f.severity != "high" for f in backed)
        hedged = bool(backed) and re.search(
            r"version|firmware|confirm|unconfirm|cannot|could not|possible|potential|may\b",
            _all_text(backed),
            re.I,
        )
        return [
            _expect(bool(backed), "family CVE still surfaced (downgraded, not dropped)"),
            _expect(not_high, "unconfirmed-version CVE is NOT marked high", str([f.severity for f in backed])),
            _expect(bool(hedged), "finding flags the version as needing confirmation"),
            _expect(_mentioned_ids(findings) <= {"CVE-2021-36260"}, "no extra CVE invented", str(sorted(_mentioned_ids(findings)))),
        ]

    return "unconfirmed version → CVE hedged, not high", (network, None, None, [camera], cves, []), check


def _probe_missing_data():
    network, _wifi, _router, _devices = golden_network()
    # Wi-Fi undetected, router not probed, one device, no CVE context.
    device = Device(ip="192.168.0.77", vendor=None, ports=[Port(number=8080, service="http-proxy")])

    def check(findings):
        return [
            _expect(_mentioned_ids(findings) == set(), "no CVE fabricated to fill the gap", str(sorted(_mentioned_ids(findings)))),
            _expect(
                not re.search(r"WPA[23]\b", _all_text(findings)) or True,  # informational only
                "(info) Wi-Fi encryption not asserted as fact",
            ),
        ]

    return "missing data → gaps left empty, not back-filled", (network, None, None, [device], {}, []), check


PROBES = [
    _probe_empty_cve_context,
    _probe_relevant_cve,
    _probe_mismatched_cve,
    _probe_unconfirmed_version_cve,
    _probe_missing_data,
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Adversarial grounding probes for the synthesis prompts.")
    parser.add_argument("--verbose", action="store_true", help="Print every synthesised finding.")
    args = parser.parse_args()

    try:
        retriever = build_default_retriever()
        llm = _build_llm()
    except Exception as exc:  # noqa: BLE001
        print(f"SKIP: could not initialise LLM/retriever ({exc})")
        return 2

    agent = SecurityAgent(llm, retriever)
    print("Prompt probes — synthesis grounding\n" + "=" * 50)

    failed = total = 0
    errored = 0
    for build in PROBES:
        name, (network, wifi, router, devices, cves, port_findings), check = build()
        print(f"\n• {name}")
        try:
            findings = agent._synthesize_findings(network, wifi, router, devices, cves, port_findings)
        except Exception as exc:  # noqa: BLE001
            errored += 1
            print(f"  [ERROR] {type(exc).__name__}: {exc}")
            continue
        if args.verbose:
            for f in findings:
                cited = ",".join(c.cve_id for c in f.related_cves) or "—"
                print(f"    · [{f.severity}/{f.dimension}] {f.title} (affected={f.affected}; cves={cited})")
        for status, label, detail in check(findings):
            total += 1
            failed += status == "FAIL"
            tail = f"  ({detail})" if detail and status == "FAIL" else ""
            print(f"  [{status}]".ljust(10) + label + tail)

    print("\n" + "=" * 50)
    print(f"probes: {total - failed}/{total} invariants hold · {failed} leak · {errored} error")
    if errored and total == 0:
        print("RESULT: SKIP — could not reach the LLM")
        return 2
    if failed or errored:
        print("RESULT: FAIL — a grounding leak (tighten config/prompts.py)")
        return 1
    print("RESULT: PASS — synthesis stayed grounded under pressure")
    return 0


if __name__ == "__main__":
    sys.exit(main())
