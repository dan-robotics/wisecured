import AppKit
import SwiftUI
import WiSecuredCore

/// Settings window: General · Checks · About & privacy (My networks / Hotspot arrive in phases 2–3).
struct SettingsView: View {
    @ObservedObject var settings: AppSettings
    let edition: Edition
    let aboutNote: String?
    @State private var launchAtLogin = false
    @State private var loginError: String?

    var body: some View {
        TabView {
            general.tabItem { Label("General", systemImage: "gearshape") }
            checks.tabItem { Label("Checks", systemImage: "checklist") }
            about.tabItem { Label("About & privacy", systemImage: "lock.shield") }
        }
        .padding(18)
        .frame(width: 560, height: 470)
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
                Text("Quad9 (backup: Cloudflare)").tag(Checker.Reference.quad9)
                Text("Cloudflare (backup: Quad9)").tag(Checker.Reference.cloudflare)
            }
            Toggle("Notify me when a network turns red", isOn: $settings.notifyOnRed)
            Toggle("Show the network name next to the menu bar icon", isOn: $settings.showNetworkName)
            privacyNote
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
        "9.9.9.9 / 1.1.1.1 (Quad9 / Cloudflare) — encrypted DNS used as the reference, reached by IP so DNS filters can't block it",
        "9.9.9.9 or 1.1.1.1 — DNSSEC test (dnssec-failed.org), plain DNS",
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
        case .pageIntegrity: return "Do web pages arrive unmodified, and is the switch to HTTPS kept?"
        case .wifiSecurity: return "Is the Wi-Fi open, broken (WEP), or encrypted (WPA2/WPA3)?"
        case .routingHealth: return "Any dead or conflicting routes, e.g. leftovers from a VPN on another network? (Read-only.)"
        }
    }
}
