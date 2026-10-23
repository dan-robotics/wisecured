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

    init() {
        fullCheckMinutes = defaults.object(forKey: "fullCheckMinutes") as? Int ?? 15
        watchSeconds = defaults.object(forKey: "watchSeconds") as? Int ?? 5
        reference = Checker.Reference(rawValue: defaults.string(forKey: "reference") ?? "") ?? .quad9
        notifyOnRed = defaults.object(forKey: "notifyOnRed") as? Bool ?? true
        showNetworkName = defaults.object(forKey: "showNetworkName") as? Bool ?? false
        hotspotSSID = defaults.string(forKey: "hotspotSSID")
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
