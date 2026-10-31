# PrivacyWatch

A standalone Flutter app that shows **who** is sending **what** personal data, **how**, and **when**, and lets you block it. It runs locally and does not send captured data anywhere.

Use it only on devices and networks you own or are authorized to monitor.

## Status

| Platform | Status |
|---|---|
| Windows | Working (tested) |
| macOS / Linux | Proxy code is portable; app identification and firewall rules are Windows-only |
| Android | UI builds; capture not implemented (planned: local `VpnService`) |
| iOS | UI builds; capture not implemented (needs a Network Extension; heavily restricted) |

## How it works

PrivacyWatch runs a local proxy on `127.0.0.1:8899`. Point Windows (Settings > Network > Proxy > Manual proxy) or an app at it.

- **Plain HTTP** is inspected for personal data: URL, headers and body.
- **HTTPS** is relayed untouched and logged as metadata only (who, destination, size, timing). Contents are never decrypted, so personal data inside HTTPS is not detected.
- Apps that ignore the system proxy are not seen at all.

## Using it

1. Click **Start monitoring**. Logging starts immediately.
2. Browse or run apps. Each transaction shows the application, destination, bytes up/down, duration and severity.
3. Click **Report / Analysis** at any time. Capture keeps running in the background; the report is a snapshot with a **Refresh** button and a live count of new transactions.
4. When something **Critical** is found, a pop-up shows the details and recommended steps, with blocking options.
5. **Stop** ends the session. The blocked list (icon in the top bar) lets you unblock.

## What it detects

Email, phone, government ID (SSN), payment card (Luhn-checked), IP address, geolocation, device/advertising ID, credentials/tokens and date of birth. Stored values are redacted (for example `41***11`).

## Severity

| Level | Examples |
|---|---|
| Critical | SSN, payment card, credentials |
| High | Date of birth, geolocation |
| Medium | Email, phone, device/advertising ID |
| Low | IP address, or contact with a known tracker |
| Info | No personal data |

Data sent over plain HTTP is raised one level because anyone on the network path can read it.

## Behavioral tracking

About 50 known analytics, advertising, telemetry and session-replay domains are labeled with owner and category ([tracker_classifier.dart](lib/core/tracker_classifier.dart)). Contact with one is flagged even when no personal data is visible. The list is not exhaustive.

## Blocking

On a Critical finding you can:

- **Block this destination:** the proxy refuses that host (and subdomains) for every application. No admin rights needed. Best for shared or legitimate programs (browser, curl, PowerShell).
- **Block this app:** the proxy refuses all traffic from that program and a Windows Firewall rule is created (Windows asks for permission). Blocks the whole program, legitimate or not, until unblocked.

Limits:

- Proxy blocks only cover traffic that goes through the proxy.
- The Windows Firewall rule is meant to cover traffic that bypasses the proxy, but it has no effect if a third-party firewall (for example Norton) is the active firewall. In testing on a Norton 360 machine the rule was reported `NotApplicable` and direct traffic was not blocked. Add the same block in that product. PrivacyWatch warns when it detects one.
- Blocks are saved to `%USERPROFILE%\PrivacyWatch\blocks.json` and restored on start. At startup PrivacyWatch also compares them with the real Windows Firewall rules: missing rules are dropped, and any leftover `PrivacyWatch block - ...` rules are adopted so you can unblock them. Creating a block reuses an existing rule instead of adding a duplicate, and unblocking removes every copy.

## Log

Every transaction is appended to `%USERPROFILE%\PrivacyWatch\transactions.jsonl` (one JSON object per line): time, severity, app and path, host, how, destination, bytes up/down, duration, tracker, and redacted matches. HTTPS tunnels are logged when they close, so byte counts are final.

## Project layout

```
lib/main.dart                     Main screen, live list, alert queue
lib/report_page.dart              Report / Analysis
lib/critical_dialog.dart          Critical pop-up and blocked list
lib/core/proxy_monitor.dart       Local forward proxy (HTTP inspect, HTTPS tunnel)
lib/core/pii_detector.dart        Personal-data categories, severity, detection
lib/core/tracker_classifier.dart  Known tracker domains
lib/core/process_resolver.dart    Owning process of a connection (Windows API)
lib/core/app_blocker.dart         App/destination blocks, firewall rules
lib/core/event.dart               Transaction model and severity
```

## Build and run (Windows)

Requires the Flutter SDK and Visual Studio Build Tools with the "Desktop development with C++" workload.

```
flutter pub get
flutter test
flutter run -d windows
```

## Roadmap

- Auto-start capture and auto-set/restore the Windows proxy
- Android local-VPN capture
- Export evidence / report
- Optional opt-in HTTPS inspection
