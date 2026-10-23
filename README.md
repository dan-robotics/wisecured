<p align="center">
  <img src="screenshots/icon.png" width="128" height="128" alt="WiSecured icon: a shield with a Wi-Fi signal">
</p>

<h1 align="center">WiSecured</h1>

<p align="center">
  <b>Public Wi-Fi, secured.</b><br>
  A macOS menu bar app that checks whether the network you're on is tampering with your connection.
</p>

<p align="center">
  <img alt="macOS 15+" src="https://img.shields.io/badge/macOS-15%2B-blue">
  <img alt="Swift 6" src="https://img.shields.io/badge/Swift-6-orange">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status: early release" src="https://img.shields.io/badge/status-early%20release-yellow">
</p>

You join a café, hotel or airport Wi-Fi. Is it honestly passing your traffic through, or is it changing DNS answers, presenting fake certificates, pretending to be the router or modifying web pages? WiSecured checks within seconds of joining, keeps watching while you stay connected, and shows **one verdict** in the menu bar:

| Shield | Verdict | Means |
|---|---|---|
| 🟢 | **Looks safe** | No tampering found |
| 🟡 | **Be careful** | Open network, a login page, a company proxy, leftover routes… |
| 🔴 | **Don't trust this network** | Tampering found — don't log in to anything here |
| ⚪ | **Checking / no network** | |

Click the shield for the details: each check says **what was seen**, **what it most likely means** (including the harmless explanation when there is one) and **what to do**. Each check's dot follows one rule: 🟢 checked and **proven** fine · 🔵 good to know, never lowers the verdict · 🟡 needs your attention · 🔴 don't trust.

WiSecured also **remembers the networks you use** (only on your Mac). Mark your home or office as **Trusted**, and it warns you when something that looks like a known network isn't the same one — the classic "evil twin".

And when a network isn't safe: **Switch to my hotspot** — one click (in the dropdown, the right-click menu or the red notification) moves you to your phone's hotspot, and **Back to …** returns you afterwards.

## The 12 checks

| # | Check | Catches |
|---|---|---|
| 1 | **Captive portal** | A login page between you and the internet (shown as info, never as danger) |
| 2 | **DNS interception** | The network secretly answering DNS questions meant for other servers |
| 3 | **DNS answers** | Fake answers sending you to fake sites — compared with encrypted DNS (your choice of Quad9, Cloudflare, Google, AdGuard or DNS4EU; Quad9 → Cloudflare → Google as backup). A rewritten answer is **red unless there's proof**: 🟡 when the address is registered to **your own internet provider** (a provider filter — the owner is named), 🟢 for a **filter device you confirmed** (e.g. your Pi-hole, recognised by its hardware ID). Blocked names (ad-blockers, filters) show as "Filtered" |
| 4 | **DNSSEC** | A network that answers in place of a validating resolver |
| 5 | **Certificates** | Fake HTTPS certificates. A trusted-but-added authority (company proxy, security software) is yellow, not red |
| 6 | **Router identity** | Something pretending to be the router: its hardware address changes, or is shared by two addresses. Watched every 5 seconds |
| 7 | **Network DNS server** | A rogue server handing out its own DNS — and DNS set by hand on the Mac (normal if you did it; DNS-changer malware does the same). Warns when that DNS **isn't reachable on the network you're on** (e.g. a home Pi-hole after you leave home) |
| 8 | **System proxy** | A proxy set on your Mac that points at an address **not on the network you're on** — traffic then hangs, or goes to whoever takes that address (often a forgotten work proxy). Through a connected work VPN it's info |
| 9 | **Page integrity** | Web pages modified in transit, or the switch to HTTPS stripped |
| 10 | **Wi-Fi security** | Open (no password) or broken (WEP) networks |
| 11 | **Known network** | Evil-twin signs: a network name you **trust** with a **different router**, or a name that was **encrypted before and is now open**. New networks and "same name, new router" (e.g. a chain café's other branch) are shown as info |
| 12 | **Routing health** | Dead or conflicting routes, e.g. leftovers from a VPN set up on another network (read-only) |

**VPN- and proxy-aware:** the network tests are pinned to the Wi-Fi (or Ethernet) interface and skip any system proxy, so a VPN, split-tunnel routes or a proxy setting don't hide the network being judged. The dropdown shows "VPN on" when a tunnel is up; a proxy gets its own check.

Full checks run when you join a network, every 15 minutes, and on **Check now**. Right-click the shield for a short menu (Check now, Trust this network, Switch to my hotspot, Settings, About, Quit). **Settings › My networks** lists every remembered network: mark it Trusted / Phone hotspot / Public, or forget it.

### Who owns that address?

A network that changes DNS answers can be an attacker — or your internet provider's filter. From your Mac the two look the same, so WiSecured looks for **evidence** instead of guessing: it asks the internet registries (RIPE, ARIN, APNIC, LACNIC, AFRINIC) who owns the rewritten address and who owns your network's own public address. Only when both belong to the same organisation (a shared registry handle or abuse-mail domain — never just a similar name) does the check turn yellow, naming the owner. Automatic when **owner lookups** are on (Settings › General, default on), or click **Who owns this?** in DNS answers. HTTPS straight to the registry, accepting **only Apple's built-in certificate authorities**, so nothing in the middle can fake the answer.

### Secure my DNS · DNS rules · Proxy Auto (all off until you turn them on)

- **Secure my DNS** (Settings › Secure DNS): creates an encrypted-DNS profile (DNS over HTTPS) for the provider you choose. You approve it in System Settings › General › Device Management and remove it there. It can stay off on networks you name (e.g. home with a Pi-hole) and leave company names to the VPN's DNS. macOS labels it "Unverified" because it's made on your Mac, not signed by a company. On a hotel login page, switch it off while you log in.
- **DNS rules** (Settings › DNS & proxy): set the DNS each remembered network should use — e.g. your Pi-hole at home, the network's own everywhere else. Applied with macOS' `networksetup` when you join; stops by itself if another tool keeps changing DNS back.
- **Proxy Auto:** mark work networks as **Office** and type your work proxy; it's switched on only there or while a work VPN is connected, and off everywhere else.

### Copy report

**Copy report** (dropdown) copies the latest check as text to share — network names, hardware addresses and local addresses masked.

### Switch to your hotspot
1. **Settings › Hotspot:** pick your phone's hotspot from your Mac's saved networks (or type its name) and type its password **once**. The password is stored only in your **macOS Keychain** — never in a file or a log; remove it there anytime.
2. When a network looks wrong, click **Switch to my hotspot**. WiSecured asks first (you'll be offline for a few seconds), joins, and re-checks.
3. **Back to "<previous network>"** returns you (it survives quitting the app), and **Switch to "<trusted network>"** offers your Trusted / Office networks; if WiSecured doesn't have a network's password it asks once (optionally remembered in the Keychain).

On an iPhone, open **Settings › Personal Hotspot** before switching — otherwise the phone isn't visible to the Mac. macOS doesn't let apps join a password-protected network without the password, which is why it's typed once.

## How to

### Choose your DNS provider (Secure my DNS)
1. Right-click the shield › **Settings…** › **Secure DNS**.
2. **Provider:** Quad9, Cloudflare, Google, AdGuard or DNS4EU.
3. **Stay off on these networks:** tick the networks where you want to keep their own DNS (e.g. home with a Pi-hole). Untick to use your provider there too.
4. Optional: **names that keep the network's / VPN's DNS**, e.g. `corp.example.com`.
5. Click **Create profile and install…**. System Settings opens: **General › Device Management › WiSecured — Secure DNS › Install** (asks for your Mac password).

From then on your Mac uses that provider on every network, encrypted. **Change provider:** pick another one and click **Create profile and install…** again — the new profile replaces the old one. **Turn it off:** **Remove or switch off…** in the same tab, then remove the profile in System Settings › General › Device Management. macOS shows the profile as "Unverified" because it's made on your Mac, not signed by a company. On a hotel login page that doesn't appear, switch Secure DNS off while you log in.

### Set the DNS for each network (DNS rules)
1. **Settings… › DNS & proxy** › switch on **DNS rules** (WiSecured asks first).
2. Next to a network, type the DNS you want, e.g. `192.168.1.53` for a Pi-hole at home, or `9.9.9.9 149.112.112.112`. Empty = that network's own DNS. Networks you haven't joined yet use their own DNS.
3. WiSecured sets it whenever you join that network (recognised by name + router). If another app or script keeps changing DNS back, DNS rules switch themselves off and tell you — switch that tool off first.

To stop: switch **DNS rules** off. Encrypted DNS everywhere is **Secure my DNS** (above); DNS rules set plain DNS addresses.

### Confirm your DNS filter ("This is my filter")
On a network marked **Trusted** whose DNS is a local device (e.g. a Pi-hole), open **DNS answers** or **Network DNS server** in the dropdown and click **This is my filter (address)**. Both turn 🟢; if a different device ever answers at that address, they turn 🔴. Remove it in **Settings › My networks › My filter devices**.

### Who owns this?
Appears under **DNS answers** only when your DNS **rewrote** an answer (sent a name to another address). It asks the internet registry who owns that address and your own network's address: same organisation → 🟡 with the owner named (a provider filter); anyone else or unknown → 🔴 stays. Blocked names (0.0.0.0, "Filtered") have nothing to look up, so no button.

## Privacy and security

- **Only looks at your Mac's own connection.** It never scans other devices and never reads anyone's traffic.
- **Watches by default.** It changes a setting only when you switch on DNS rules or Proxy Auto (both off by default); Secure DNS is a profile you install and remove yourself. No admin rights or helper tools.
- **Local.** No account, no cloud, no telemetry, no analytics.
- **No third-party dependencies.** Apple frameworks only.
- **Wi-Fi passwords you type into WiSecured** (your hotspot, optionally networks to go back to) live **only in your macOS Keychain**, under WiSecured's own entry.
- **Network memory stays on your Mac:** for each network, its name, router hardware address, access points, strongest security seen and your Trusted / Hotspot / Public choice — in the app's own Application Support folder, readable only by you.
- **Outside contacts — the test lookups and nothing else** (also listed in Settings › About & privacy):
  - `captive.apple.com`, `detectportal.firefox.com` — login-page and page-integrity tests (plain HTTP)
  - `www.apple.com` — checks that the switch to HTTPS is kept
  - `9.9.9.9` / `1.1.1.2` / `8.8.8.8` — Quad9 (threat blocking + DNSSEC), Cloudflare (malware blocking + DNSSEC), Google (DNSSEC): encrypted DNS (DoH) used as the reference, your choice first, reached by IP so DNS filters can't block it; plain DNS for the DNSSEC test (`dnssec-failed.org`)
  - `192.0.2.53` — a reserved test address where nothing lives (any answer = interception)
  - `www.apple.com`, `www.google.com`, `www.cloudflare.com`, `www.wikipedia.org`, `github.com` — certificate check (connects, sends nothing)
  - your network's / your Mac's own DNS server — the same test names
  - `94.140.14.14` (AdGuard) / `86.54.11.1` (DNS4EU) — only when you choose them as the reference
  - `1.1.1.1` (HTTPS) — your network's public address, to find its internet provider (owner lookups on)
  - `rdap.db.ripe.net`, `rdap.arin.net`, `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net` (HTTPS) — who owns your provider's address and any rewritten DNS answer (owner lookups on, or when you click "Who owns this?"). The registry learns which address was asked about; your own address it already sees
- **Filter devices you confirm** (address, hardware ID, network) are stored in the same folder.

### Permissions it asks for

| Permission | Why | Without it |
|---|---|---|
| **Location** | macOS only shows Wi-Fi names and security types to apps with Location permission. Your location itself is never used or stored | Checks still run; network name and Wi-Fi security are unknown |
| **Local Network** | To ask your network's DNS server and read your router's address | DNS-answer and router checks can't run |
| **Notifications** | One alert when a network turns red (with a "Switch to my hotspot" button) | Menu bar colour only |
| **Keychain** (only if you set a hotspot) | Keep the hotspot password you typed | No one-click switching; use the Wi-Fi menu |

## Install

1. Download the latest `WiSecured-<version>.dmg` from [**Releases**](https://github.com/dan-robotics/wisecured/releases/latest) and, optionally, check it: `shasum -a 256 WiSecured-*.dmg` against `SHA256SUMS.txt`.
2. Open the DMG and drag **WiSecured** onto **Applications**.
3. First launch: the app is ad-hoc signed, not notarized, so macOS blocks it once. Open it, then **System Settings › Privacy & Security › Open Anyway**.
4. Allow **Location**, **Local Network** and **Notifications** when asked. A shield appears in the menu bar.

Prefer not to run a downloaded binary? Build it yourself:

```bash
git clone https://github.com/dan-robotics/wisecured.git
cd wisecured
swift test        # 62 tests: every check's outcomes from simulated readings (no network)
./build.sh        # → dist/<version>-<timestamp>/WiSecured.app + dist/WiSecured-<version>-<timestamp>.dmg
```

Needs the Xcode command line tools with Swift 6.

## What it can't do

- **See a purely passive listener.** On an open network someone can listen without changing anything; WiSecured can only warn that the network is open.
- **Catch an attacker who targets only some sites, some of the time**, between checks.
- **See inside your provider or router.** It only sees what reaches your Mac. When a DNS answer is rewritten it shows the evidence (who owns the address); without proof it stays red.

## FAQ

**Red "Fake answers" at home?** Some internet providers filter DNS (security or parental filters) and send blocked names to their own servers. Open **DNS answers › Who owns this?** — if the address belongs to your own provider, the check turns yellow and names it. To avoid it: switch the filter off in your provider account, or use **Secure my DNS**.

**My Pi-hole shows blue.** Mark your home as Trusted, open DNS answers (or Network DNS server) and choose **This is my filter** — from then on it's green, and red if a different device ever answers at that address.

## Status and roadmap

**Early release (0.5.0).** 0.4.x was tested on a MacBook Pro M1 Pro, macOS 27.0.1: at home (with a DNS filter), on an iPhone hotspot (including switching to it and back) and with a VPN connected. 0.5.0's verdict rules are covered by tests with simulated readings, and its owner lookups and five reference providers were checked live; on-screen testing of the new settings is in progress. **Not yet tested on real public Wi-Fi** — reports welcome (use **Copy report**).

Ideas for later: screenshots from real public Wi-Fi, notarized builds.

## Project layout

```
Package.swift
Sources/CNetInfo/          C: the Mac's own address table (router identity) + routing table, read-only
Sources/WiSecuredCore/     the checks (pure functions), network tests, verdict rules, network memory, Wi-Fi switching
Sources/WiSecuredUI/       menu bar shield, dropdown, settings, scheduling, notifications
Sources/WiSecured/         app entry point
Tests/WiSecuredCoreTests/  simulated-reading tests
tools/make-icon.swift      draws the app icon
build.sh                   builds the .app + DMG
```

## Credits

Built with [Claude Code](https://claude.com/claude-code).

## License

[MIT](LICENSE) © 2026 Daniel Andries
