# Phase 6 — Regression & Prompt-Convergence Log (B)

A captured, reproducible record of the agent-layer regression suite and the
prompt-convergence pass. The scripts live in [`scripts/`](../scripts) and can be
re-run at any time; this file preserves a representative run (and the one
*before* state that no longer exists in the code) so the result is traceable in
the report without re-running anything.

**Environment:** Azure OpenAI chat (deployment per `.env`) + `text-embedding-3-small`,
**temperature 0**; ChromaDB KB of 5,355 CVE chunks + 200 KB chunks. Captured
**2026-06-05** at `HEAD = afdf572`.

**Reproduce:**

```bash
.venv/bin/python scripts/golden_scan.py                         # deterministic, no LLM / no network
.venv/bin/python scripts/prompt_probes.py --verbose             # synthesis grounding (live LLM)
.venv/bin/python scripts/qa_regression.py                       # Q&A grounding on the golden report (live LLM)
.venv/bin/python scripts/qa_regression.py --report data/sample_report.json   # …or against a real saved scan
```

## What each regression guards

| Script | Mechanism | Asserts | LLM? |
| ------ | --------- | ------- | ---- |
| `golden_scan.py` | Runs the fixed `golden_fixtures` network through `reporter.assemble_report`, plus a rubric table. | Grade **C** reproduced, 2H/3M/1L, findings sorted, CVE rendered, all 5 dimensions, dedup remediation, **every A–F branch**. | No |
| `prompt_probes.py` | Feeds `SecurityAgent._synthesize_findings` crafted CVE contexts (empty / relevant / mismatched / unconfirmed-version / missing). | No invented CVE, provided CVE cited & attributed to the right host, mismatched CVE not mis-pinned, family-only/unknown-version CVE hedged (not high), gaps left empty. | Yes |
| `qa_regression.py` | Runs a fixed question bank through `SecurityAgent.ask`; grade/CVE anchors read live from the report. | Each answer cites real report facts (`any_of`) and fabricates none (`none_of`); runs against the golden report or any saved scan. | Yes |

---

## Captured run — 2026-06-05 (`HEAD = afdf572`)

### 1. `golden_scan.py` — 25/25

```text
[report assembly]
  [PASS]  overall grade is C
  [PASS]  severity mix 2H/3M/1L
  [PASS]  findings sorted worst-first
  [PASS]  header counts rendered
  [PASS]  device count in header
  [PASS]  CVE id cited in Markdown
  [PASS]  all five dimensions report a finding
  [PASS]  dimension rendered: Router vulnerability
  [PASS]  dimension rendered: Wi-Fi encryption
  [PASS]  dimension rendered: IoT exposure
  [PASS]  dimension rendered: Network isolation
  [PASS]  dimension rendered: Remote attack surface
  [PASS]  6 remediation steps (deduplicated)
  [PASS]  remediation ordered high → low

[grading rubric]
  [PASS]  grade A: clean network
  [PASS]  grade A: info only never lowers
  [PASS]  grade B: single low
  [PASS]  grade B: single medium
  [PASS]  grade B: three medium (below the 4-medium cutoff)
  [PASS]  grade C: four medium
  [PASS]  grade C: one high
  [PASS]  grade C: proposal anchor: 2 high + 3 medium + 1 low
  [PASS]  grade D: three high
  [PASS]  grade D: four high
  [PASS]  grade F: five high

checks: 25/25 pass · 0 fail
RESULT: PASS — golden scan reproduced exactly
```

### 2. `prompt_probes.py --verbose` — 10/10

> This is the pinned 2026-06-05 capture (4 probes / 10 invariants). A 5th probe
> and the version-confidence prompt change landed 2026-06-09 — see
> *"Update 2026-06-09"* below; the current suite reports **14/14**.

```text
• empty CVE context → no invented CVE
    · [medium/wifi_encryption] Wi-Fi uses WPA2 only (affected=Wi-Fi SSID HomeNet; cves=—)
    · [medium/network_isolation] No guest or IoT network isolation shown (affected=Home network 192.168.0.0/24; cves=—)
    · [medium/remote_attack_surface] UPnP is enabled on the router (affected=Router 192.168.0.1 (BusyBox gateway); cves=—)
    · [low/remote_attack_surface] Router admin page is reachable on your home network (affected=Router 192.168.0.1 (BusyBox gateway admin panel); cves=—)
  [PASS]  no CVE cited from empty context
  [PASS]  no CVE id invented in prose
  [PASS]  still synthesises non-CVE findings

• relevant CVE → cited and correctly attributed
    · [medium/wifi_encryption] Wi-Fi uses WPA2 only (affected=Wi-Fi SSID HomeNet; cves=—)
    · [medium/network_isolation] No guest or IoT network isolation shown (affected=Home network 192.168.0.0/24; cves=—)
    · [medium/remote_attack_surface] UPnP is enabled on the router (affected=192.168.0.1 BusyBox gateway; cves=—)
    · [low/remote_attack_surface] Router admin page is reachable on the home network (affected=192.168.0.1 BusyBox gateway admin panel; cves=—)
    · [high/router_vulnerability] Router software matches a known BusyBox CVE (affected=192.168.0.1 BusyBox gateway / BusyBox httpd 1.19.4; cves=CVE-2018-5371)
  [PASS]  the provided CVE is cited
  [PASS]  CVE attributed to the gateway, not another host
  [PASS]  no extra CVE invented

• mismatched CVE → not forced onto an unrelated host
    · [info/wifi_encryption] Wi-Fi security could not be checked (affected=Wi-Fi network; cves=—)
    · [info/network_isolation] Network isolation was not verified (affected=Home network; cves=—)
    · [high/router_vulnerability] Known BusyBox router vulnerability (affected=Gateway 192.168.0.1 (BusyBox gateway); cves=CVE-2018-5371)
    · [info/remote_attack_surface] UPnP appears to be off (affected=Gateway 192.168.0.1; cves=—)
    · [low/remote_attack_surface] Router admin panel not exposed externally (affected=Gateway 192.168.0.1; cves=—)
  [PASS]  router CVE not mis-pinned onto the laptop
  [PASS]  no extra CVE invented

• missing data → gaps left empty, not back-filled
    · [info/wifi_encryption] Wi-Fi security could not be checked (affected=Wi-Fi network; cves=—)
    · [info/network_isolation] Guest or IoT isolation was not verified (affected=Home network segmentation; cves=—)
  [PASS]  no CVE fabricated to fill the gap
  [PASS]  (info) Wi-Fi encryption not asserted as fact

probes: 10/10 invariants hold · 0 leak · 0 error
RESULT: PASS — synthesis stayed grounded under pressure
```

### 3. `qa_regression.py` (golden report) — 8/8

```text
report: grade C, 6 findings, source: golden_fixtures (synthetic)

Q1. What overall security grade did my home network receive, and what are the main reasons?
  [PASS] Your home network received a **C — Needs improvement**. Main reasons from your scan: 1. **Router ri…
Q2. Which device or service on my network has the most serious problem?
  [PASS] The most serious issue in this scan is your **router at 192.168.0.1**, specifically its **web admin…
Q3. Is my Wi-Fi encryption strong enough, or should I change it?
  [PASS] Your Wi-Fi is using **WPA2** on **"HomeNet"**, which is **okay but not the strongest option**. For …
Q4. Which CVE was found on my router, and how severe is it?
  [PASS] The scan found **CVE-2018-5371** on your router at **192.168.0.1**. - **Affected component:** BusyB…
Q5. If I can only fix one thing first, what should it be?
  [PASS] Fix the **router firmware first**. Why this is the best first step on your network: - Your gateway …
Q6. Do I have a separate guest or IoT network, or is everything on one subnet?
  [PASS] Everything appears to be on one subnet. From your scan: - Your local network is **192.168.0.0/24** …
Q7. Is there a smart thermostat on my network, and what is its IP address?
  [PASS] Based on this scan, **no smart thermostat was identified**. The scan found these 3 devices: - **192…
Q8. Does my network have the Heartbleed vulnerability?
  [PASS] Based on this scan, I can't say that your network has Heartbleed. What the scan did find: - Your ro…

grounded: 8/8 pass · 0 fail · 0 blocked · 0 skipped · 0 error
RESULT: PASS — every answer stayed grounded in the report
```

---

## Prompt convergence: measured before → after

The probes showed the synthesis prompts were **already grounded** (10/10, zero
CVE leaks), so no anti-hallucination change was warranted. The only real wobble
was a **severity drift**: the *“router admin page reachable on the LAN”* finding
came out at a different severity depending on the run — which can nudge the
overall grade at a boundary. The fix was to anchor that (and missing-data)
severity in [`config/prompts.py`](../config/prompts.py) (commit `f5968e9`).

Same probe, admin-panel finding, before vs after the anchor:

```text
BEFORE (probe run e46eae9, pre-anchor prompt):
  empty CVE context  → [low /remote_attack_surface] Router admin page is available on the local network
  relevant CVE        → [info/remote_attack_surface] Router admin page is available on the local network   ← drift (low vs info)

AFTER (HEAD afdf572, anchored prompt):
  empty CVE context  → [low /remote_attack_surface] Router admin page is reachable on your home network
  relevant CVE        → [low /remote_attack_surface] Router admin page is reachable on the home network    ← stable (low both runs)
```

The anchor block added to `AGENT_SYSTEM_PROMPT`:

> For these recurring home cases, classify consistently so the grade stays
> stable run to run: WEP/open → high, WPA2 without WPA3 → medium, UPnP on →
> medium, no guest/IoT isolation → medium, **admin panel reachable only from
> the LAN → low**, data that could not be collected → info (never a guessed
> value).

### Update 2026-06-09 — CVE version confidence (probes 4→5, 10→14 invariants)

A new probe (`_probe_unconfirmed_version_cve`) feeds a high-CVSS CVE (Hikvision
`CVE-2021-36260`, CVSS 9.8) for a device whose **running version is unknown**.
Before, `AGENT_SYSTEM_PROMPT`'s "CVSS ≥ 7.0 → high" rule plus the synthesis
prompt's "whenever a CVE is listed, raise it" forced a confident **high** for any
same-family match. The prompts now gate severity on version confidence:

```text
BEFORE: [high/iot_exposure]   Hikvision camera vulnerable to CVE-2021-36260
AFTER:  [medium/iot_exposure] Possible Hikvision firmware vulnerability (CVE-2021-36260) — verify firmware version
```

Confirmed matches still stay high (the BusyBox httpd **1.19.4** probe continues
to report `[high] … CVE-2018-5371`). Full suite at this HEAD:
**golden 25/25 · probes 14/14 · Q&A 8/8**.

## Notes (honesty)

- `golden_scan.py` is the only fully deterministic gate; the two LLM gates run
  at temperature 0 but can still vary slightly — re-run once if a single check
  flickers.
- Against the **live** saved scan (`--report data/sample_report.json`), the
  out-of-scope probe is sometimes refused by Azure's own content filter
  (`cyber_policy`); `qa_regression.py` reports that as a non-fatal `BLOCK`, not a
  grounding failure.
- The matcher was tuned during bring-up to avoid two false positives: smart
  quotes (`can’t`) and the substring-negation trap (`no confirmed Heartbleed`
  ≠ a fabricated *“confirmed Heartbleed”*).
