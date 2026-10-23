import Foundation
import CoreWLAN

/// Phase 3: joins a Wi-Fi network chosen by the user (their phone hotspot, or back to the previous
/// network). The password is passed in memory to Apple's Wi-Fi framework — never written to a
/// file, a log or a command line. Only ever called after the user confirmed the switch.
public enum WiFiSwitch {
    public enum Outcome: Sendable, Equatable {
        case joined(String)
        case notInRange(String)
        case failed(String, code: Int)

        public var succeeded: Bool { if case .joined = self { return true }; return false }

        /// One plain sentence for the dropdown.
        public var message: String {
            switch self {
            case .joined(let ssid): return "Switched to \"\(ssid)\"."
            case .notInRange(let ssid):
                return "\"\(ssid)\" isn't visible. On an iPhone, open Settings › Personal Hotspot and keep that screen open, then try again."
            case .failed(let ssid, let code): return "Couldn't join \"\(ssid)\": \(WiFiSwitch.explain(code))"
            }
        }
    }

    /// Joins `ssid` with `password` (nil = open network). Blocks for a few seconds — call off the
    /// main thread.
    public static func join(ssid: String, password: String?) -> Outcome {
        guard let iface = CWWiFiClient.shared().interface() else { return .failed(ssid, code: -1) }
        do {
            let found = try iface.scanForNetworks(withName: ssid)
            guard let network = found.max(by: { $0.rssiValue < $1.rssiValue }) else { return .notInRange(ssid) }
            try iface.associate(to: network, password: password)
            return .joined(ssid)
        } catch let error as NSError {
            return .failed(ssid, code: error.code)
        }
    }

    /// The SSID the Mac is on right now (needs Location permission).
    public static func currentSSID() -> String? { CWWiFiClient.shared().interface()?.ssid() }

    /// Whether a saved network needs a password (from the Mac's saved-network list).
    public static func isOpen(_ ssid: String) -> Bool {
        NetworkReader.savedNetworks().first { $0.ssid == ssid }?.security.hasPrefix("Open") ?? false
    }

    /// CoreWLAN error codes → what to do.
    public static func explain(_ code: Int) -> String {
        switch code {
        case -3900: return "the password was missing or not accepted. Check it in Settings › Hotspot."
        case -3905: return "it took too long. Move closer or try again."
        case -3906, -3902: return "the Wi-Fi didn't accept the connection. Try again in a moment."
        case -3908, -3909, -3913: return "the network refused the connection (wrong password, or it is full)."
        case -1: return "no Wi-Fi interface was found."
        default: return "macOS reported error \(code)."
        }
    }
}
