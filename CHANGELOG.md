# Changelog

## [0.2.1] — 2026-10-23 — First public release

- Menu bar shield with one verdict: Looks safe / Be careful / Don't trust this network / Checking.
- 10 checks: captive portal, DNS interception, DNS answers vs encrypted DNS (Quad9, Cloudflare backup; reached by IP), DNSSEC, certificates (company proxies = yellow), router identity (watched every 5 s), network DNS server (incl. DNS set by hand on the Mac), page integrity / HTTPS stripping, Wi-Fi security, routing health (read-only).
- Network tests pinned to the Wi-Fi / Ethernet interface, so a VPN doesn't hide the network being judged; "VPN on" shown.
- A pending login page never produces a false red.
- Dropdown with "Seen / Means / Do" for every check; right-click menu; settings; one notification per network and problem; launch at login.
- Read-only, local, no telemetry, no third-party dependencies. 24 tests from simulated readings.

Earlier versions were private development builds.
