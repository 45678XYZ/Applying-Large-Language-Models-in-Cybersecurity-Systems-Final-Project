# Home Network Security Audit Report

**Generated:** 2026-06-05 11:20  
**Overall grade:** D — At risk  
**Devices discovered:** 2 | High: 3 · Medium: 2 · Low: 0

## Network Summary

- **Local host:** 192.168.30.50 (192.168.30.0/24) on en0 (wireless)
- **Gateway:** 192.168.30.1
- **DNS:** 192.168.30.1, 8.8.8.8
- **Wi-Fi:** SSID "OldHome" · WPA2 · 2.4GHz
- **Router:** BusyBox gateway · firmware 1.19.4 · admin panel exposed (at 192.168.30.1)

## Devices

- **192.168.30.1** — old-router.local [gateway] · 3 open: 23/tcp telnet, 80/tcp http, 1900/udp upnp
- **192.168.30.18** — nas.local · 1 open: 445/tcp microsoft-ds

## Findings

### 🔴 High

1. **Router firmware matches a high-severity BusyBox CVE** — 192.168.30.1 port 80/tcp
   The gateway exposes BusyBox httpd 1.19.4, which matches a high-severity CVE returned by the knowledge base.
   *Related CVEs:* CVE-2018-5371 (CVSS 8.8)
   *Recommendation:* Upgrade or replace the router firmware before the demo network is reused.

2. **Telnet is open on the gateway** — 192.168.30.1 port 23/tcp
   BusyBox telnetd is reachable on 23/tcp. Telnet sends credentials without encryption and is frequently targeted by automated attacks.
   *Recommendation:* Disable Telnet and use a hardened SSH or local-only admin path instead.

3. **UPnP can open WAN ports automatically** — 192.168.30.1 port 1900/udp
   MiniUPnP 1.8 is reachable on UDP 1900, allowing LAN devices to request inbound port forwards without manual review.
   *Recommendation:* Disable UPnP unless a documented device needs it.

### 🟡 Medium

1. **Weak Wi-Fi posture on the router SSID** — SSID "OldHome"
   OldHome still uses WPA2 on a 2.4GHz-only SSID with a weak signal margin.
   *Recommendation:* Move the SSID to WPA3 or WPA2/WPA3 mixed mode and review the passphrase.

2. **NAS shares the router subnet** — 192.168.30.0/24
   The NAS sits on the same subnet as the vulnerable gateway, so a router compromise can immediately reach file-sharing services.
   *Recommendation:* Put storage devices behind a management VLAN or host firewall rules.

## Risk Dimensions

- **Router vulnerability:** 🔴 High (1 finding)
- **Wi-Fi encryption:** 🟡 Medium (1 finding)
- **IoT exposure:** ✅ no issues found
- **Network isolation:** 🟡 Medium (1 finding)
- **Remote attack surface:** 🔴 High (2 findings)

## Prioritised Remediation

1. 🔴 Upgrade or replace the router firmware before the demo network is reused.
2. 🔴 Disable Telnet and use a hardened SSH or local-only admin path instead.
3. 🔴 Disable UPnP unless a documented device needs it.
4. 🟡 Move the SSID to WPA3 or WPA2/WPA3 mixed mode and review the passphrase.
5. 🟡 Put storage devices behind a management VLAN or host firewall rules.
