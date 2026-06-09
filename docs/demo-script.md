# Phase 6 Demo Script (Member A)

This is the deterministic fallback demo path for screenshots and presentation
practice. It keeps the final demo independent of the live LAN state while still
rendering the same Streamlit UI used by `app.py`.

## Reproduce

```bash
python scripts/demo_scenarios.py --list
python scripts/demo_scenarios.py --export --out docs/demo-reports
streamlit run app.py
```

In the Streamlit sidebar, choose **Demo scenario** and click **Load Demo Report**.
For automated screenshot capture, the same reports can be opened directly:

```text
http://localhost:8501/?demo=clean_network
http://localhost:8501/?demo=risky_iot
http://localhost:8501/?demo=vulnerable_router
```

## UI Walkthrough

### 1. Idle Home Screen

- Sidebar shows **Run**, the red **Start Scan** button, **Demo scenario** set to
  `Risky IoT`, **Load Demo Report**, and **Reset**.
- Main area shows **Home Network Security Auditor** with the subtitle
  `Sequential LAN scan, CVE lookup, graded report, and grounded follow-up Q&A.`
- The onboarding banner says to click **Start Scan** for a live network audit or
  **Load Demo Report** for the deterministic example.
- Feature cards are **Discover devices**, **Match real CVEs**,
  **Graded A-F report**, and **Grounded Q&A**.
- The scan settings row shows **Top 100 ports**, **On - root**, and
  **Local LAN**.

### 2. Running Scan State

- Click **Start Scan**.
- Sidebar button changes to `Scanning...`; the status text reads:
  `Probing the router at 172.20.10.1... | Looking up known CVEs... | Assessing open-port risks...`.
- The progress panel title is **Running scan** and includes:
  `Reading local network configuration...`, `Checking Wi-Fi security...`,
  `Scanning 172.20.10.0/28 for devices... (with OS detection)`,
  `Found 2 device(s).`, `Probing the router at 172.20.10.1...`,
  `Looking up known CVEs...`, and `Assessing open-port risks...`.

### 3. Risky IoT Report Summary

- Load `Risky IoT`.
- Show the **Security Report** header with grade **B**, label **Good**, chips
  **2 devices**, **2 Medium**, and **Generated 2026-06-09 15:59**.
- Network fields should match the screenshot:
  `Local IP 172.20.10.2`, `Subnet 172.20.10.0/28`,
  `Gateway 172.20.10.1`, `Interface en0`, `DNS 172.20.10.1`,
  and `Medium Wireless`.
- Captions should read `Wi-Fi: <redacted> | WPA3 | 2.4GHz | -31 dBm` and
  `Router 172.20.10.1: unknown model`.

### 4. Risk Dimensions, Devices, And Findings

- Risk Dimensions table:
  `Router vulnerability = None / 0`,
  `Wi-Fi encryption = Info / 1`,
  `IoT exposure = Medium / 1`,
  `Network isolation = Info / 1`,
  `Remote attack surface = Medium / 3`.
- Devices table:
  `172.20.10.1` as **Gateway**, OS
  `Apple iOS 15.0 - 16.1 (Darwin 21.1.0 - 22.1.0) (100% accuracy)`,
  ports `21/tcp ftp, 53/tcp domain, 49152/tcp tcpwrapped`.
- Devices table:
  `172.20.10.2`, OS
  `Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0) (100% accuracy)`,
  port `5000/tcp rtsp`.
- Findings tabs show **High**, **Medium**, **Low**, **Info**. The High tab says
  `No high findings.` and the **Markdown report** expander is collapsed.
- Follow-up Q&A initial message:
  `Scan complete. The network received grade B. Ask a follow-up question about the findings or remediation steps.`

### 5. Chinese Follow-Up Q&A

- Ask: `請幫我用中文簡要地解釋掃描結果`
- The answer should briefly explain:
  - overall grade **B (Good)**;
  - only **2 devices** were found;
  - `172.20.10.1` is the gateway/router and `172.20.10.2` is the Mac;
  - good news: Wi-Fi uses **WPA3**;
  - items to verify: gateway FTP on `21/tcp`, RTSP on `5000/tcp`, and
    `49152/tcp tcpwrapped`.

## Scenario Notes

### Clean Network

- Select `Clean network`.
- Show the grade **A** header, WPA3 Wi-Fi summary, two discovered devices, and
  the empty findings state.
- Talk track: the auditor does not manufacture risks when the fixture has no
  findings, so the report remains quiet and the grade stays A.

### Risky IoT

- Select `Risky IoT`.
- Show the grade **B** header, two discovered devices, WPA3 Wi-Fi, and the
  mixed Medium/Info risk dimensions from the modified UI screenshots.
- Talk track: this screenshot set demonstrates the real scan flow on a small
  local LAN. The network is mostly healthy, but the report still calls out
  reachable FTP/RTSP-style services and asks the user to verify whether they
  are intentional.

### Vulnerable Router

- Select `Vulnerable router`.
- Show the grade **D** header, the gateway ports, and the high-severity tab.
- Call out `CVE-2018-5371` in the finding card and Markdown report.
- Talk track: this covers the acceptance criterion that at least one high-risk
  finding cites a real CVE retrieved from the KB-backed flow.

## Screenshot Checklist

The updated UI screenshot artifacts are:

- `docs/demo-screenshots/home-start.png`
- `docs/demo-screenshots/scan-running.png`
- `docs/demo-screenshots/risky-iot-report.png`
- `docs/demo-screenshots/risky-iot-report-details.png`
- `docs/demo-screenshots/risky-iot-qa-zh.png`

Legacy scenario screenshots are still kept for comparison:

- `docs/demo-screenshots/clean-network-report.png`
- `docs/demo-screenshots/vulnerable-router-report.png`

The exported Markdown/JSON reports live under `docs/demo-reports/` and are safe
to regenerate whenever the report renderer changes.
