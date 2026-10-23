import AppKit
import SwiftUI
import WiSecuredCore

/// Settings window: General · My networks · Hotspot · Secure DNS · DNS & proxy · Checks · About & privacy.
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
    @State private var secureStatus: String?
    @State private var proxyPortText = ""

    var body: some View {
        TabView {
            general.tabItem { Label("General", systemImage: "gearshape") }
            networksTab.tabItem { Label("My networks", systemImage: "wifi") }
            hotspotTab.tabItem { Label("Hotspot", systemImage: "personalhotspot") }
            secureTab.tabItem { Label("Secure DNS", systemImage: "lock.icloud") }
            rulesTab.tabItem { Label("DNS & proxy", systemImage: "arrow.triangle.branch") }
            checks.tabItem { Label("Checks", systemImage: "checklist") }
            about.tabItem { Label("About & privacy", systemImage: "lock.shield") }
        }
        .padding(18)
        .frame(width: 720, height: 560)
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
                ForEach(Checker.Reference.allCases, id: \.self) { Text("\($0.name) · \($0.address) — \($0.features)").tag($0) }
            }
            Toggle("Look up who owns addresses (your provider's, and any rewritten DNS answer)", isOn: $settings.ownerLookups)
            Text("Asks the internet registries (RIPE, ARIN, APNIC, LACNIC, AFRINIC) over HTTPS, accepting only Apple's built-in certificate authorities. They learn which address was asked about — your own address they already see. Off: \"Who owns this?\" still works when you click it.")
                .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
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
                Text("Trusted = your home. Office = a work network (Proxy Auto turns your proxy on there). Automatic = phone hotspots are recognised, everything else counts as public. Stored only on this Mac: network name, router hardware address, access points, strongest security seen.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Section {
                if monitor.filterDevices.isEmpty {
                    Text("None yet. On a Trusted network, open DNS answers or Network DNS server in the dropdown and choose \"This is my filter\" for your Pi-hole (or similar).")
                        .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                ForEach(monitor.filterDevices) { device in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(device.address).font(.system(size: 13, weight: .semibold))
                            Text("on \(device.networkName) · hardware ID \(device.mac) · added \(device.added.formatted(date: .abbreviated, time: .omitted))")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Remove") { monitor.removeFilter(device.id) }.buttonStyle(.borderless)
                    }
                }
            } header: {
                Text("My filter devices")
            } footer: {
                Text("A confirmed filter answering on its own network, with the same hardware ID, shows green. Another device at that address shows red.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: Secure DNS (P5)

    private var trustedWiFiNames: [String] {
        var seen = Set<String>()
        return monitor.networks.filter { $0.kind.isTrustedLike }.compactMap(\.ssid).filter { seen.insert($0).inserted }
    }

    private var secureTab: some View {
        Form {
            Section {
                Picker("Provider", selection: $settings.secureProvider) {
                    ForEach(Checker.Reference.allCases, id: \.self) { Text("\($0.name) — \($0.features)").tag($0) }
                }
                Text("Encrypts your Mac's DNS everywhere, so no network can read or change it. Off until you install it; macOS asks you to approve it.")
                    .font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } header: { Text("Secure my DNS") }
            Section {
                if trustedWiFiNames.isEmpty {
                    Text("No Trusted or Office Wi-Fi yet. Mark your home (e.g. with a Pi-hole) as Trusted so Secure DNS can stay off there.")
                        .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                ForEach(trustedWiFiNames, id: \.self) { name in
                    Toggle(name, isOn: Binding(get: { settings.secureSkipNetworks.contains(name) }, set: { on in
                        settings.secureSkipNetworks.removeAll { $0 == name }
                        if on { settings.secureSkipNetworks.append(name) }
                    }))
                }
            } header: { Text("Stay off on these networks") } footer: {
                Text("Your own DNS (e.g. a Pi-hole) keeps working there.").font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Section {
                TextField("e.g. corp.example.com, intranet.local", text: $settings.secureSkipDomains)
            } header: { Text("Names that keep the network's / VPN's DNS") } footer: {
                Text("For company names that only the work VPN or office DNS knows.").font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Section {
                HStack {
                    Button("Create profile and install…") { installSecureDNS() }.buttonStyle(.borderedProminent).tint(Theme.accent)
                    Button("Remove or switch off…") { openProfiles() }
                }
                if let secureStatus { Text(secureStatus).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                Text("macOS shows the profile as \"Unverified\": it's made on your Mac by WiSecured, not signed by a company (that needs a paid Apple developer account). Approve it in System Settings › General › Device Management. On a hotel login page, switch Secure DNS off while you log in. Changing the options above? Install again — it replaces the old one.")
                    .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .onAppear {
            if settings.secureSkipNetworks.isEmpty && settings.secureProfileCreated == nil { settings.secureSkipNetworks = trustedWiFiNames }
        }
    }

    private func installSecureDNS() {
        let data = SecureDNSProfile.make(provider: settings.secureProvider, skipNetworks: settings.secureSkipNetworks,
                                         skipDomains: SecureDNSProfile.domains(from: settings.secureSkipDomains), bundleID: Monitor.bundleID)
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent(Monitor.bundleID, isDirectory: true)
        let file = base.appendingPathComponent("WiSecured-Secure-DNS.mobileconfig")
        do {
            try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try data.write(to: file, options: .atomic)
        } catch {
            secureStatus = "Couldn't write the profile: \(error.localizedDescription)"
            return
        }
        NSWorkspace.shared.open(file)
        settings.secureProfileCreated = Date()
        secureStatus = "Profile handed to macOS. Now approve it: System Settings › General › Device Management › WiSecured — Secure DNS › Install."
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { openProfiles() }
    }

    private func openProfiles() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Profiles-Settings.extension") { NSWorkspace.shared.open(url) }
    }

    // MARK: DNS rules (L5) + Proxy Auto (S1)

    private var rulesTab: some View {
        Form {
            Section {
                Toggle("DNS rules", isOn: Binding(get: { settings.dnsRulesOn }, set: { monitor.setDNSRules($0) }))
                Text("Off: WiSecured only watches. On: it sets your Mac's DNS whenever you join one of these networks (recognised by name + router). Unlisted networks get their own DNS.")
                    .font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                ForEach(monitor.networks.sorted { $0.lastSeen > $1.lastSeen }) { record in
                    HStack {
                        Text(record.displayName).frame(width: 170, alignment: .leading).lineLimit(1)
                        Text(record.kind.label).font(.system(size: 11)).foregroundStyle(.secondary).frame(width: 80, alignment: .leading)
                        TextField("Network's DNS", text: Binding(get: {
                            settings.dnsRules[record.id]?.servers.joined(separator: ", ") ?? ""
                        }, set: { text in
                            let list = Automation.validAddresses(text)
                            settings.dnsRules[record.id] = list.isEmpty ? nil : .custom(list)
                        }))
                        .disabled(!settings.dnsRulesOn)
                    }
                }
            } header: { Text("DNS rules") } footer: {
                Text("Empty = the network's DNS (or Secure DNS, if installed). Type addresses, e.g. your Pi-hole, for your home. Only valid addresses are kept.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Section {
                Picker("Proxy", selection: $settings.proxyMode) {
                    ForEach(ProxyMode.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                HStack {
                    TextField("Proxy address", text: $settings.proxyHost)
                    TextField("Port", text: $proxyPortText).frame(width: 80)
                        .onChange(of: proxyPortText) { _, text in settings.proxyPort = Int(text) ?? 0 }
                }
                .disabled(settings.proxyMode == .notManaged)
            } header: { Text("Proxy Auto") } footer: {
                Text("Auto turns your web proxy on only on networks marked Office (My networks) or while a work VPN is connected (Tailscale doesn't count), and off everywhere else — so a work proxy never hangs your traffic on other networks. Kept only on this Mac.")
                    .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Text("Changes are made with macOS' networksetup, as you. Both are off by default.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .onAppear { proxyPortText = settings.proxyPort > 0 ? String(settings.proxyPort) : "" }
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
                Text("Everything stays on this Mac: no account, no cloud, no telemetry, no admin rights. WiSecured only looks at this Mac's own connection — it never scans other devices or reads anyone's traffic. It changes a setting only when you switch on DNS rules or Proxy Auto (both off by default); Secure DNS is a profile you install and remove yourself.")
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
        "9.9.9.9 / 1.1.1.2 / 8.8.8.8 / 94.140.14.14 / 86.54.11.1 (Quad9 / Cloudflare / Google / AdGuard / DNS4EU, your choice first, then Quad9 → Cloudflare → Google) — encrypted DNS used as the reference, reached by IP so DNS filters can't block it",
        "The same address of your chosen service — DNSSEC test (dnssec-failed.org), plain DNS",
        "192.0.2.53 — reserved test address (nothing lives there; any answer = interception)",
        "www.apple.com, www.google.com, www.cloudflare.com, www.wikipedia.org, github.com — certificate check (connects, sends nothing)",
        "The DNS server your Mac uses (or the network's) — test names a.root-servers.net, k.root-servers.net, one.one.one.one, dns.google, dns.quad9.net",
        "1.1.1.1 (HTTPS) — this network's public address, to find its internet provider (owner lookups on)",
        "rdap.db.ripe.net, rdap.arin.net, rdap.apnic.net, rdap.lacnic.net, rdap.afrinic.net (HTTPS) — who owns your provider's address and any rewritten DNS answer (owner lookups on, or when you click \"Who owns this?\")",
    ]

    static func explain(_ id: CheckID) -> String {
        switch id {
        case .captivePortal: return "Is there a login page between you and the internet? (Shown as info, never as danger.)"
        case .dnsInterception: return "Does the network secretly answer DNS questions meant for other servers?"
        case .dnsAnswers: return "Do well-known names resolve to the right addresses, compared with encrypted DNS? A rewritten answer is red unless there's proof: green for a filter device you confirmed, yellow when the address belongs to your own internet provider (a provider filter)."
        case .dnssec: return "Do DNS questions reach a validating resolver unchanged?"
        case .certificates: return "Do well-known HTTPS sites present genuine certificates? (A company proxy shows as yellow.)"
        case .routerIdentity: return "Is the router still the same device? Watched every few seconds."
        case .networkDNS: return "Who answers your DNS: the router, a public service, your confirmed filter, or another device? Warns when DNS set by hand points somewhere this network can't reach."
        case .systemProxy: return "Is a proxy set on this Mac — and does it point at an address that isn't on the network you're on (traffic hangs, or goes to whoever takes that address)?"
        case .pageIntegrity: return "Do web pages arrive unmodified, and is the switch to HTTPS kept?"
        case .wifiSecurity: return "Is the Wi-Fi open, broken (WEP), or encrypted (WPA2/WPA3)?"
        case .networkMemory: return "Is this a network you know, and is it the same one? Warns when a trusted name has a different router, or a name that was encrypted is now open (evil-twin signs). Remembered only on this Mac."
        case .routingHealth: return "Any dead or conflicting routes, e.g. leftovers from a VPN on another network? (Read-only.)"
        }
    }
}
