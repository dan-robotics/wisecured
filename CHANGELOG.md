# Changelog

## [0.4.1] — 2026-10-23 — System proxy check; tests skip proxies

- **System proxy** (12th check): warns (🟡) when a proxy set on your Mac points at a private address that isn't on the network you're on — plain web traffic then hangs, or goes to whoever takes that address (often a forgotten work proxy). A proxy on this network, a local proxy app, a public proxy or automatic proxy configuration are shown as info.
- **Fixed:** with such a proxy set, the captive-portal and page-integrity tests hung and showed "Couldn't test". All test connections now skip system proxies, so WiSecured always tests the network itself.
- 39 tests.


## [0.4.0] — 2026-10-23 — Switch to your hotspot and back

- **Settings › Hotspot:** pick your own phone hotspot and type its password once — stored only in the macOS Keychain (WiSecured's own entry); remove it anytime. A list of saved Wi-Fi passwords with Delete.
- **Switch to my hotspot** in the dropdown (prominent when the network isn't safe), the right-click menu and as a **button on the red notification**. **Back to "<previous network>"** afterwards (asks for that network's password once if needed, optionally remembered). Every switch asks first; a full check runs right after.
- Joins happen in-process with the password only in memory — never on a command line, in a file or a log. Clear messages when it can't join (hotspot not visible, password not accepted, …).
- 34 tests.


## [0.3.0] — 2026-10-23 — Network memory, evil-twin warnings, Google as a reference

- **Known network** (11th check): networks you use are remembered on your Mac (name, router hardware address, access points, strongest security seen). Warns (yellow) when a **trusted** name shows up with a **different router**, or a name that was **encrypted is now open / WEP** — classic evil-twin signs. New networks and "same name, new router" (another branch of a chain café) are info. A network judged "don't trust" is never remembered.
- **Trust this network** in the dropdown and the right-click menu; **Settings › My networks** to mark Trusted / Phone hotspot / Public or forget a network. Dropdown tag shows Trusted / Phone hotspot / Public.
- **Reference DNS:** choose Quad9 (9.9.9.9, threat blocking + DNSSEC), Cloudflare (now **1.1.1.2**, malware blocking + DNSSEC) or **Google** (8.8.8.8, DNSSEC); the others are the backup, in order. All reached by IP; certificates checked valid for the IPs.
- 33 tests.


## [0.2.1] — 2026-10-23 — First public release

- Menu bar shield with one verdict: Looks safe / Be careful / Don't trust this network / Checking.
- 10 checks: captive portal, DNS interception, DNS answers vs encrypted DNS (Quad9, Cloudflare backup; reached by IP), DNSSEC, certificates (company proxies = yellow), router identity (watched every 5 s), network DNS server (incl. DNS set by hand on the Mac), page integrity / HTTPS stripping, Wi-Fi security, routing health (read-only).
- Network tests pinned to the Wi-Fi / Ethernet interface, so a VPN doesn't hide the network being judged; "VPN on" shown.
- A pending login page never produces a false red.
- Dropdown with "Seen / Means / Do" for every check; right-click menu; settings; one notification per network and problem; launch at login.
- Read-only, local, no telemetry, no third-party dependencies. 24 tests from simulated readings.

Earlier versions were private development builds.
