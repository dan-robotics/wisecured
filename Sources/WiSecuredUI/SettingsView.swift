import AppKit
import SwiftUI
import WiSecuredCore

/// Settings window: General · Checks · About & privacy (My networks / Hotspot arrive in phases 2–3).
struct SettingsView: View {
    @ObservedObject var settings: AppSettings
    @ObservedObject var monitor: Monitor
    let edition: Edition
    let aboutNote: String?
    @State private var launchAtLogin = false
    @State private var loginError: String?
    @State private var pickedHotspot = ""
    @State private var hotspotPassword = ""
    @State private var hotspotStatus: String?
    @State private var savedNetworks: [SavedNetwork] = []
    @State private var rememberedPasswords: [String] = []

    var body: some View {
        TabView {
            general.tabItem { Label("General", systemImage: "gearshape") }
            networksTab.tabItem { Label("My networks", systemImage: "wifi") }
            hotspotTab.tabItem { Label("Hotspot", systemImage: "personalhotspot") }
            checks.tabItem { Label("Checks", systemImage: "checklist") }
            about.tabItem { Label("About & privacy", systemImage: "lock.shield") }
        }
        .padding(18)
        .frame(width: 600, height: 500)
        .onAppear { launchAtLogin = settings.launchAtLogin }
    }

    private var general: some View {
        Form {
            Toggle("Launch at login", isOn: Binding(get: { launchAtLogin }, set: { on in
                loginError = settings.setLaunchAtLogin(on)
                launchAtLogin = settings.launchAtLogin
            }))
            if let loginError { Text(loginError).font(.caption).foregroundStyle(.red) }
            Picker("Full check", selection: $settings.fullCheckMinutes) {
                ForEach(AppSettings.fullCheckChoices, id: \.minutes) { Text($0.label).tag($0.minutes) }
            }
            Picker("Watch the router", selection: $settings.watchSeconds) {
                ForEach(AppSettings.watchChoices, id: \.seconds) { Text($0.label).tag($0.seconds) }
            }
            Picker("Compare DNS with", selection: $settings.reference) {
                Text("Quad9 · 9.9.9.9 — threat blocking + DNSSEC").tag(Checker.Reference.quad9)
                Text("Cloudflare · 1.1.1.2 — malware blocking + DNSSEC").tag(Checker.Reference.cloudflare)
                Text("Google · 8.8.8.8 — DNSSEC").tag(Checker.Reference.google)
            }
            Toggle("Notify me when a network turns red", isOn: $settings.notifyOnRed)
            Toggle("Show the network name next to the menu bar icon", isOn: $settings.showNetworkName)
            privacyNote
        }
        .formStyle(.grouped)
    }

    private var hotspotTab: some View {
        Form {
            Section {
                Picker("Hotspot", selection: $pickedHotspot) {
                    Text("Choose…").tag("")
                    ForEach(savedNetworks.map(\.ssid), id: \.self) { Text($0).tag($0) }
                    if !pickedHotspot.isEmpty && !savedNetworks.contains(where: { $0.ssid == pickedHotspot }) {
                        Text(pickedHotspot).tag(pickedHotspot)
                    }
                }
                TextField("…or type its Wi-Fi name", text: $pickedHotspot)
                SecureField(WiFiPasswords.has(pickedHotspot) ? "Password (saved — type to replace)" : "Password", text: $hotspotPassword)
                HStack {
                    Button("Save hotspot") { saveHotspot() }.disabled(pickedHotspot.isEmpty)
                    if let current = settings.hotspotSSID {
                        Button("Remove \"\(current)\"", role: .destructive) { removeHotspot(current) }
                    }
                }
                if let hotspotStatus { Text(hotspotStatus).font(.system(size: 11.5)).foregroundStyle(.secondary) }
            } header: {
                Text("Your phone hotspot")
            } footer: {
                Text("Used by \"Switch to my hotspot\" (dropdown, right-click menu, red notifications). The name is kept in WiSecured's settings; the password only in your Mac's Keychain. Before switching to an iPhone hotspot, open Settings › Personal Hotspot on the phone so the Mac can see it.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Section("Saved Wi-Fi passwords (Keychain)") {
                if rememberedPasswords.isEmpty {
                    Text("None.").font(.system(size: 12)).foregroundStyle(.secondary)
                }
                ForEach(rememberedPasswords, id: \.self) { ssid in
                    HStack {
                        Text(ssid)
                        if ssid == settings.hotspotSSID { Text("hotspot").font(.caption).foregroundStyle(.secondary) }
                        Spacer()
                        Button("Delete") { WiFiPasswords.delete(ssid); rememberedPasswords = WiFiPasswords.allSSIDs() }.buttonStyle(.borderless)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear {
            pickedHotspot = settings.hotspotSSID ?? ""
            savedNetworks = NetworkReader.savedNetworks()
            rememberedPasswords = WiFiPasswords.allSSIDs()
        }
    }

    private func saveHotspot() {
        let ssid = pickedHotspot.trimmingCharacters(in: .whitespaces)
        guard !ssid.isEmpty else { return }
        if !hotspotPassword.isEmpty {
            if let error = WiFiPasswords.save(hotspotPassword, for: ssid) { hotspotStatus = "Couldn't save the password: \(error)"; return }
        } else if !WiFiPasswords.has(ssid) && !WiFiSwitch.isOpen(ssid) {
            hotspotStatus = "Type the hotspot's password (it's saved only in your Keychain)."
            return
        }
        settings.hotspotSSID = ssid
        hotspotPassword = ""
        rememberedPasswords = WiFiPasswords.allSSIDs()
        hotspotStatus = "Saved: \"\(ssid)\". The password is in your Keychain."
    }

    private func removeHotspot(_ ssid: String) {
        WiFiPasswords.delete(ssid)
        settings.hotspotSSID = nil
        pickedHotspot = ""
        rememberedPasswords = WiFiPasswords.allSSIDs()
        hotspotStatus = "Removed. Its password was deleted from the Keychain."
    }

    private var networksTab: some View {
        Form {
            Section {
                if monitor.networks.isEmpty {
                    Text("No networks remembered yet. Each network you join is remembered after its first check.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                ForEach(monitor.networks.sorted { $0.lastSeen > $1.lastSeen }) { record in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(record.displayName).font(.system(size: 13, weight: .semibold))
                            Text("Last seen \(record.lastSeen.formatted(date: .abbreviated, time: .shortened)) · \(record.timesSeen) visit\(record.timesSeen == 1 ? "" : "s")\(record.lastSecurity.map { " · \($0)" } ?? "")")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Picker("", selection: Binding(get: { record.kind }, set: { monitor.setKind(record.id, $0) })) {
                            ForEach(RememberedNetwork.Kind.allCases, id: \.self) { Text($0.label).tag($0) }
                        }
                        .labelsHidden().frame(width: 140)
                        Button("Forget") { monitor.forget(record.id) }.buttonStyle(.borderless)
                    }
                }
            } header: {
                Text("Remembered networks")
            } footer: {
                Text("Trusted = your home or office. Automatic = phone hotspots are recognised, everything else counts as public. Stored only on this Mac: network name, router hardware address, access points, strongest security seen.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private var checks: some View {
        Form {
            Section("What WiSecured checks") {
                ForEach(CheckID.allCases, id: \.self) { id in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(id.title).font(.system(size: 13, weight: .semibold))
                        Text(Self.explain(id)).font(.system(size: 11.5)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var about: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 10) {
                        Image(nsImage: Shield.image(for: .safe, size: 34))
                        VStack(alignment: .leading) {
                            Text("WiSecured").font(.system(size: 16, weight: .bold))
                            Text("Public Wi-Fi, secured. · Version \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev")\(aboutNote.map { " · \($0)" } ?? "")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Section("Privacy") {
                Text("Everything stays on this Mac: no account, no cloud, no telemetry, no admin rights. WiSecured only looks at this Mac's own connection — it never scans other devices or reads anyone's traffic, and never changes a setting or a route.")
                    .font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
            }
            Section("Outside contacts (the test lookups, nothing else)") {
                ForEach(Self.contacts, id: \.self) { Text($0).font(.system(size: 12)) }
            }
        }
        .formStyle(.grouped)
    }

    private var privacyNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(nsImage: Shield.image(for: .safe, size: 18))
            Text("Everything stays on this Mac. WiSecured only contacts the test addresses listed under About & privacy.")
                .font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    static let contacts = [
        "captive.apple.com, detectportal.firefox.com — login-page and page-integrity tests (plain HTTP)",
        "www.apple.com — checks that the switch to HTTPS is kept",
        "9.9.9.9 / 1.1.1.2 / 8.8.8.8 (Quad9 / Cloudflare / Google, your choice first) — encrypted DNS used as the reference, reached by IP so DNS filters can't block it",
        "The same address of your chosen service — DNSSEC test (dnssec-failed.org), plain DNS",
        "192.0.2.53 — reserved test address (nothing lives there; any answer = interception)",
        "www.apple.com, www.google.com, www.cloudflare.com, www.wikipedia.org, github.com — certificate check (connects, sends nothing)",
        "The DNS server your Mac uses (or the network's) — test names a.root-servers.net, k.root-servers.net, one.one.one.one, dns.google, dns.quad9.net",
    ]

    static func explain(_ id: CheckID) -> String {
        switch id {
        case .captivePortal: return "Is there a login page between you and the internet? (Shown as info, never as danger.)"
        case .dnsInterception: return "Does the network secretly answer DNS questions meant for other servers?"
        case .dnsAnswers: return "Do well-known names resolve to the right addresses, compared with encrypted DNS?"
        case .dnssec: return "Do DNS questions reach a validating resolver unchanged?"
        case .certificates: return "Do well-known HTTPS sites present genuine certificates? (A company proxy shows as yellow.)"
        case .routerIdentity: return "Is the router still the same device? Watched every few seconds."
        case .networkDNS: return "Who answers your DNS: the router, a public service, or another device on the network?"
        case .systemProxy: return "Is a proxy set on this Mac — and does it point at an address that isn't on the network you're on (traffic hangs, or goes to whoever takes that address)?"
        case .pageIntegrity: return "Do web pages arrive unmodified, and is the switch to HTTPS kept?"
        case .wifiSecurity: return "Is the Wi-Fi open, broken (WEP), or encrypted (WPA2/WPA3)?"
        case .networkMemory: return "Is this a network you know, and is it the same one? Warns when a trusted name has a different router, or a name that was encrypted is now open (evil-twin signs). Remembered only on this Mac."
        case .routingHealth: return "Any dead or conflicting routes, e.g. leftovers from a VPN on another network? (Read-only.)"
        }
    }
}
