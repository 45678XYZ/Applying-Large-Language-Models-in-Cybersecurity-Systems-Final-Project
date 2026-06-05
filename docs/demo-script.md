# Phase 6 Demo Script (Member A)

This is the deterministic fallback demo path for screenshots and presentation
practice. It keeps the final demo independent of the live LAN state while still
rendering the same `ScanReport` UI used by `app.py`.

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

## Scenario 1: Clean Network

- Select `Clean network`.
- Show the grade **A** header, WPA3 Wi-Fi summary, two discovered devices, and
  the empty findings state.
- Talk track: the auditor does not manufacture risks when the fixture has no
  findings, so the report remains quiet and the grade stays A.

## Scenario 2: Risky IoT

- Select `Risky IoT`.
- Show the grade **C** header, the camera and thermostat in the device table,
  and the medium findings for RTSP, HTTP admin, WPA2, and missing isolation.
- Talk track: this is a common home-network failure mode. Nothing needs a CVE
  to be useful; the report still prioritizes segmentation and password hygiene.

## Scenario 3: Vulnerable Router

- Select `Vulnerable router`.
- Show the grade **D** header, the gateway ports, and the high-severity tab.
- Call out `CVE-2018-5371` in the finding card and Markdown report.
- Talk track: this covers the acceptance criterion that at least one high-risk
  finding cites a real CVE retrieved from the KB-backed flow.

## Screenshot Checklist

The final-report screenshot artifacts are:

- `docs/demo-screenshots/clean-network-report.png`
- `docs/demo-screenshots/risky-iot-report.png`
- `docs/demo-screenshots/vulnerable-router-report.png`

The exported Markdown/JSON reports live under `docs/demo-reports/` and are safe
to regenerate whenever the report renderer changes.
