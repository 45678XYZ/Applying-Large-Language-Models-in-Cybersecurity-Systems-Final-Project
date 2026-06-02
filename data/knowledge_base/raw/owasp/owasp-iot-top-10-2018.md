# OWASP IoT Top 10 — 2018 Edition

Source: OWASP Internet of Things Project, https://owasp.org/www-project-internet-of-things/

The OWASP IoT Top 10 enumerates the ten categories of risk most commonly
seen in Internet-connected consumer and enterprise devices. Each item
below is a chunk-sized unit covering: the risk, how it typically
manifests on a home network, and concrete mitigations.

---

## I1 — Weak, Guessable, or Hardcoded Passwords

Use of easily brute-forced, publicly available, or unchangeable credentials,
including firmware-level backdoor accounts. This is the single most common
root cause of IoT compromise.

Common manifestations on a home network:
- Default admin / admin or admin / password still in use on the router web UI
- IP cameras shipped with a vendor-wide fixed password (e.g. Hikvision "12345")
- Telnet or SSH services accepting vendor-defined backdoor accounts
- Firmware containing hardcoded service accounts used for remote management

Mitigations: force a password change on first boot, disable any account
that cannot be rotated, deny known-default credential lists at the device
level, and audit firmware for hardcoded credentials before release.

---

## I2 — Insecure Network Services

Unneeded or insecure network services running on the device itself,
especially services exposed to the broader Internet, that can compromise
the confidentiality, integrity / authenticity, or availability of data.

Common manifestations on a home network:
- Telnet (TCP 23) open by default on routers and IP cameras
- UPnP (UDP 1900) enabled, allowing internal services to be punched through NAT
- Debug or test interfaces (e.g. tcp/9999, tcp/4444) left listening on production firmware
- RTSP (TCP 554) exposed without authentication on IP cameras

Mitigations: ship with the smallest possible listening surface, disable
remote-management protocols by default, require authentication on every
service, and never expose internal-only services to WAN.

---

## I3 — Insecure Ecosystem Interfaces

Insecure web, backend API, cloud, or mobile interfaces in the ecosystem
outside of the device that allow compromise of the device or its related
components. Common issues include lack of authentication / authorisation,
lacking or weak encryption, and lack of input / output filtering.

Common manifestations:
- Companion mobile apps talking to backend APIs over HTTP instead of HTTPS
- Cloud APIs without rate limiting, allowing credential stuffing
- Web admin panels with CSRF, XSS, or path-traversal vulnerabilities
- Mobile app secrets (API keys, signing keys) embedded in plaintext

Mitigations: enforce TLS everywhere with certificate pinning where feasible,
implement strong authentication and least-privilege authorisation on all
APIs, validate and sanitise all inputs, and rotate secrets out of clients.

---

## I4 — Lack of Secure Update Mechanism

Lack of ability to securely update the device. This includes lack of firmware
validation on device, lack of secure delivery (un-encrypted in transit), lack
of anti-rollback mechanisms, and lack of notifications of security changes
due to updates.

Common manifestations:
- Firmware downloaded over plain HTTP, making MITM-injected updates possible
- No cryptographic signature check before installing a new image
- Update servers reachable but no anti-rollback, allowing downgrade to a vulnerable build
- Devices that simply have no update mechanism at all (typical of low-end IoT)

Mitigations: serve firmware over TLS, verify signatures against a vendor
public key burned into ROM, implement monotonic version counters to block
downgrades, and notify users when an update changes security posture.

---

## I5 — Use of Insecure or Outdated Components

Use of deprecated or insecure software components / libraries that could
allow the device to be compromised. This includes insecure customisation of
operating system platforms, and the use of third-party software or hardware
components from a compromised supply chain.

Common manifestations:
- Routers running BusyBox / dnsmasq / OpenSSL versions years out of date
- Vulnerable Linux kernels with known LPE exploits
- Re-used IoT chipsets that ship with vendor SDKs containing known CVEs

Mitigations: maintain a software bill of materials (SBOM), subscribe to
upstream CVE feeds for every component, ship security patches within a
declared service window, and avoid silently abandoning device firmware.

---

## I6 — Insufficient Privacy Protection

User's personal information stored on the device or in the ecosystem that is
used insecurely, improperly, or without permission.

Common manifestations:
- Voice-assistant or smart-camera devices uploading recordings to vendor cloud without explicit consent
- Routers logging visited domains and shipping logs to vendor analytics
- Mobile apps requesting permissions far beyond device functionality
- PII (names, addresses, photos) stored unencrypted on the device's filesystem

Mitigations: minimise collected data, gain explicit consent for any
collection, encrypt PII at rest, document data flows in user-facing
documentation, and offer a data deletion path.

---

## I7 — Insecure Data Transfer and Storage

Lack of encryption or access control of sensitive data anywhere within the
ecosystem, including at rest, in transit, or during processing.

Common manifestations:
- Wi-Fi credentials stored in plaintext on the device filesystem
- Sensor data transmitted to the cloud over MQTT without TLS
- Configuration backups exported as unencrypted plaintext
- Internal debug logs containing session tokens written to persistent storage

Mitigations: encrypt sensitive data on disk (full-disk or per-record),
require TLS on every external connection, scrub secrets from logs, and
limit access to sensitive data based on least privilege.

---

## I8 — Lack of Device Management

Lack of security support on devices deployed in production, including asset
management, update management, secure decommissioning, systems monitoring,
and response capabilities.

Common manifestations:
- No central inventory of which devices are deployed, with which firmware
- No mechanism to push a security patch fleet-wide
- Decommissioned devices retain credentials / API keys, becoming attacker beachheads
- Anomalous behaviour on the device produces no log forwarded to the operator

Mitigations: maintain a device registry, implement remote update and config
management, log security events to a central collector, and define a secure
decommissioning procedure including key revocation.

---

## I9 — Insecure Default Settings

Devices or systems shipped with insecure default settings, or lack the
ability to make the system more secure by restricting operators from
modifying configurations.

Common manifestations:
- Wi-Fi printed on a sticker with WPS PIN enabled
- Remote management (HTTPS / Telnet / SSH) reachable from WAN by default
- Cloud / vendor-management features turned on out of box
- Configuration options hidden or locked behind hidden "advanced" pages

Mitigations: ship with the most restrictive sensible defaults, require a
deliberate user action to enable each remote-exposed feature, surface
security-relevant settings prominently in the UI, and avoid hiding
configuration that affects security posture.

---

## I10 — Lack of Physical Hardening

Lack of physical hardening measures, allowing potential attackers to gain
sensitive information that can help in a future remote attack, or take
local control of the device.

Common manifestations:
- Exposed UART / JTAG headers on a PCB enabling firmware extraction
- Bootloader without password protection, allowing console root access
- Removable storage (SD card, eMMC) containing unencrypted firmware
- No tamper-evident enclosure or detection

Mitigations: disable debug interfaces in production firmware, enable
secure boot, encrypt on-board storage, and design enclosures that signal
tamper attempts.
