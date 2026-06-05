# Home Network Security Audit Report

**Generated:** 2026-06-05 11:20  
**Overall grade:** C — Needs improvement  
**Devices discovered:** 4 | High: 0 · Medium: 4 · Low: 0

## Network Summary

- **Local host:** 192.168.20.44 (192.168.20.0/24) on wlan0 (wireless)
- **Gateway:** 192.168.20.1
- **DNS:** 192.168.20.1
- **Wi-Fi:** SSID "FamilyNet" · WPA2 · 2.4GHz
- **Router:** ISP gateway · firmware 2025.10 (at 192.168.20.1)

## Devices

- **192.168.20.1** — router.local [gateway] · 2 open: 53/tcp domain, 443/tcp https
- **192.168.20.23** — frontdoor-cam.local · 1 open: 554/tcp rtsp
- **192.168.20.24** — thermostat.local · 1 open: 80/tcp http
- **192.168.20.42** — laptop.local [Windows] · no open ports

## Findings

### 🟡 Medium

1. **Wi-Fi uses WPA2 rather than WPA3** — SSID "FamilyNet"
   FamilyNet negotiates WPA2. It is acceptable for compatibility, but weaker than WPA3 against offline password cracking.
   *Recommendation:* Enable WPA3 or WPA2/WPA3 mixed mode if all devices support it.

2. **IP camera exposes RTSP on the main LAN** — 192.168.20.23 port 554/tcp
   frontdoor-cam.local exposes RTSP on 554/tcp, a common target for default-password checks and stream scraping.
   *Recommendation:* Move cameras to an IoT VLAN or guest SSID and rotate their passwords.

3. **Thermostat serves an unencrypted HTTP admin page** — 192.168.20.24 port 80/tcp
   thermostat.local exposes HTTP on 80/tcp, so admin traffic can be observed by any host on the same LAN segment.
   *Recommendation:* Disable the local admin page or restrict it to a management VLAN.

4. **Personal devices and IoT devices share one subnet** — 192.168.20.0/24
   The camera, thermostat, and laptop all sit on 192.168.20.0/24, so one compromised IoT device can directly reach the laptop.
   *Recommendation:* Create a guest or IoT SSID that cannot initiate connections to laptops.

## Risk Dimensions

- **Router vulnerability:** ✅ no issues found
- **Wi-Fi encryption:** 🟡 Medium (1 finding)
- **IoT exposure:** 🟡 Medium (2 findings)
- **Network isolation:** 🟡 Medium (1 finding)
- **Remote attack surface:** ✅ no issues found

## Prioritised Remediation

1. 🟡 Enable WPA3 or WPA2/WPA3 mixed mode if all devices support it.
2. 🟡 Move cameras to an IoT VLAN or guest SSID and rotate their passwords.
3. 🟡 Disable the local admin page or restrict it to a management VLAN.
4. 🟡 Create a guest or IoT SSID that cannot initiate connections to laptops.
