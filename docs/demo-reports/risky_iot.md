# Home Network Security Audit Report

**Generated:** 2026-06-09 15:59
**Overall grade:** B - Good
**Devices discovered:** 2 | High: 0 | Medium: 2 | Low: 0 | Info: 4

## Network Summary

- **Local host:** 172.20.10.2 (172.20.10.0/28) on en0 (wireless)
- **Gateway:** 172.20.10.1
- **DNS:** 172.20.10.1
- **Wi-Fi:** SSID "<redacted>" | WPA3 | 2.4GHz | -31 dBm
- **Router:** unknown model (at 172.20.10.1)

## Devices

- **172.20.10.1** [gateway] [Apple iOS 15.0 - 16.1 (Darwin 21.1.0 - 22.1.0) (100% accuracy)] | 3 open: 21/tcp ftp, 53/tcp domain, 49152/tcp tcpwrapped
- **172.20.10.2** [Apple macOS 12 (Monterey) (Darwin 21.1.0 - 21.6.0) (100% accuracy)] | 1 open: 5000/tcp rtsp

## Findings

### Medium

1. **RTSP service is reachable on the local host** - 172.20.10.2 port 5000/tcp
   172.20.10.2 exposes RTSP on 5000/tcp. Media services should be limited to trusted clients and kept off shared networks when possible.
   *Recommendation:* Restrict RTSP to trusted devices or disable it when it is not needed.

2. **Gateway exposes FTP** - 172.20.10.1 port 21/tcp
   172.20.10.1 has FTP open on 21/tcp, which can expose credentials or files if enabled unintentionally.
   *Recommendation:* Disable FTP on the gateway unless it is required for a known management workflow.

### Info

1. **Wi-Fi uses WPA3** - SSID "<redacted>"
   The active wireless network uses WPA3 with a strong signal.
   *Recommendation:* Keep WPA3 enabled and continue using a strong passphrase.

2. **Small local subnet was scanned** - 172.20.10.0/28
   The scan covered 172.20.10.0/28 and found only the gateway and local host.
   *Recommendation:* Keep untrusted IoT devices on a guest or IoT SSID when they are added.

3. **Gateway provides DNS locally** - 172.20.10.1 port 53/tcp
   172.20.10.1 answers DNS on 53/tcp for the local network.
   *Recommendation:* Leave DNS reachable only from the LAN and avoid exposing it to the internet.

4. **Gateway has a tcpwrapped high port** - 172.20.10.1 port 49152/tcp
   172.20.10.1 exposes 49152/tcp as tcpwrapped, which indicates access control is present but the service should be identified.
   *Recommendation:* Confirm which gateway service owns 49152/tcp and disable it if it is unnecessary.

## Risk Dimensions

- **Router vulnerability:** no issues found
- **Wi-Fi encryption:** Info (1 finding)
- **IoT exposure:** Medium (1 finding)
- **Network isolation:** Info (1 finding)
- **Remote attack surface:** Medium (3 findings)

## Prioritised Remediation

1. Restrict RTSP to trusted devices or disable it when it is not needed.
2. Disable FTP on the gateway unless it is required for a known management workflow.
3. Confirm which gateway service owns 49152/tcp and disable it if it is unnecessary.
