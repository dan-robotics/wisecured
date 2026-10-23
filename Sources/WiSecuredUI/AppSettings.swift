import Foundation
import Combine
import ServiceManagement
import WiSecuredCore

/// User preferences, stored in UserDefaults (this app's own domain only).
@MainActor
final class AppSettings: ObservableObject {
    static let fullCheckChoices: [(minutes: Int, label: String)] = [(15, "On network change + every 15 min"),
                                                                     (5, "On network change + every 5 min"),
                                                                     (0, "On network change only")]
    static let watchChoices: [(seconds: Int, label: String)] = [(5, "Every 5 s"), (15, "Every 15 s"), (0, "Off")]

    private let defaults = UserDefaults.standard

    @Published var fullCheckMinutes: Int { didSet { defaults.set(fullCheckMinutes, forKey: "fullCheckMinutes") } }
    @Published var watchSeconds: Int { didSet { defaults.set(watchSeconds, forKey: "watchSeconds") } }
    @Published var reference: Checker.Reference { didSet { defaults.set(reference.rawValue, forKey: "reference") } }
    @Published var notifyOnRed: Bool { didSet { defaults.set(notifyOnRed, forKey: "notifyOnRed") } }
    @Published var showNetworkName: Bool { didSet { defaults.set(showNetworkName, forKey: "showNetworkName") } }
    /// The user's own phone hotspot (Wi-Fi name). Its password lives in the Keychain, never here.
    @Published var hotspotSSID: String? { didSet { defaults.set(hotspotSSID, forKey: "hotspotSSID") } }
    /// P7: the network to go "Back to" after switching to the hotspot (survives restarts).
    @Published var previousSSID: String? { didSet { defaults.set(previousSSID, forKey: "previousSSID") } }

    /// Q1: look up who owns your provider's address and any rewritten address (registries, HTTPS).
    @Published var ownerLookups: Bool { didSet { defaults.set(ownerLookups, forKey: "ownerLookups") } }

    /// P5 Secure my DNS — the profile is only ever installed by the user, in System Settings.
    @Published var secureProvider: Checker.Reference { didSet { defaults.set(secureProvider.rawValue, forKey: "secureProvider") } }
    @Published var secureSkipNetworks: [String] { didSet { defaults.set(secureSkipNetworks, forKey: "secureSkipNetworks") } }
    @Published var secureSkipDomains: String { didSet { defaults.set(secureSkipDomains, forKey: "secureSkipDomains") } }
    /// When the user last opened a profile for installing (WiSecured can't read whether it was approved).
    @Published var secureProfileCreated: Date? { didSet { defaults.set(secureProfileCreated, forKey: "secureProfileCreated") } }

    /// L5 DNS rules: off by default; per remembered network (by its id).
    @Published var dnsRulesOn: Bool { didSet { defaults.set(dnsRulesOn, forKey: "dnsRulesOn") } }
    @Published var dnsRules: [UUID: DNSRule] { didSet { defaults.set(try? JSONEncoder().encode(dnsRules), forKey: "dnsRules") } }

    /// S1 Proxy Auto: the user's own proxy, typed in Settings (never in the source).
    @Published var proxyMode: ProxyMode { didSet { defaults.set(proxyMode.rawValue, forKey: "proxyMode") } }
    @Published var proxyHost: String { didSet { defaults.set(proxyHost, forKey: "proxyHost") } }
    @Published var proxyPort: Int { didSet { defaults.set(proxyPort, forKey: "proxyPort") } }

    init() {
        fullCheckMinutes = defaults.object(forKey: "fullCheckMinutes") as? Int ?? 15
        watchSeconds = defaults.object(forKey: "watchSeconds") as? Int ?? 5
        reference = Checker.Reference(rawValue: defaults.string(forKey: "reference") ?? "") ?? .quad9
        notifyOnRed = defaults.object(forKey: "notifyOnRed") as? Bool ?? true
        showNetworkName = defaults.object(forKey: "showNetworkName") as? Bool ?? false
        hotspotSSID = defaults.string(forKey: "hotspotSSID")
        previousSSID = defaults.string(forKey: "previousSSID")
        ownerLookups = defaults.object(forKey: "ownerLookups") as? Bool ?? true
        secureProvider = Checker.Reference(rawValue: defaults.string(forKey: "secureProvider") ?? "") ?? .quad9
        secureSkipNetworks = defaults.stringArray(forKey: "secureSkipNetworks") ?? []
        secureSkipDomains = defaults.string(forKey: "secureSkipDomains") ?? ""
        secureProfileCreated = defaults.object(forKey: "secureProfileCreated") as? Date
        dnsRulesOn = defaults.object(forKey: "dnsRulesOn") as? Bool ?? false
        dnsRules = (defaults.data(forKey: "dnsRules")).flatMap { try? JSONDecoder().decode([UUID: DNSRule].self, from: $0) } ?? [:]
        proxyMode = ProxyMode(rawValue: defaults.string(forKey: "proxyMode") ?? "") ?? .notManaged
        proxyHost = defaults.string(forKey: "proxyHost") ?? ""
        proxyPort = defaults.object(forKey: "proxyPort") as? Int ?? 0
    }

    var launchAtLogin: Bool { SMAppService.mainApp.status == .enabled }

    /// Returns an error message, or nil on success.
    func setLaunchAtLogin(_ on: Bool) -> String? {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            return nil
        } catch {
            return error.localizedDescription
        }
    }
}
