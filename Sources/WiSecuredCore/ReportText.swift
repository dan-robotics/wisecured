import Foundation

/// P8 "Copy report": the latest check as plain text for sharing (e.g. a tester sending results).
/// Network names, hardware IDs and local addresses are masked; public addresses (the evidence,
/// e.g. where a DNS answer was sent) and owners stay.
public enum ReportText {
    public static func make(_ report: Report, version: String, names: [String]) -> String {
        var lines: [String] = []
        lines.append("WiSecured \(version) report — \(report.date.formatted(date: .abbreviated, time: .shortened))")
        lines.append("Verdict: \(report.verdict.title)")
        lines.append(report.reason)
        var network = report.network.isWiFi ? "Wi-Fi · \(report.network.security)" : (report.network.interfaceName == nil ? "No network" : "Wired")
        network += report.network.vpnOn ? " · VPN on" : " · VPN off"
        lines.append("Network: \(network)")
        if let provider = report.provider { lines.append("Internet provider: \(provider.labelWithCountry)") }
        lines.append("")
        for f in report.findings {
            lines.append("[\(symbol(f.status))] \(f.id.title): \(f.summary)")
            lines.append("    Seen: \(f.seen)")
        }
        lines.append("")
        lines.append("Masked: network names, hardware IDs and local addresses. Public addresses are kept as evidence.")
        return mask(lines.joined(separator: "\n"), names: names + [report.network.ssid].compactMap { $0 })
    }

    static func symbol(_ status: CheckStatus) -> String {
        switch status {
        case .ok: return "OK"
        case .info: return "INFO"
        case .warn: return "WARN"
        case .danger: return "RED"
        case .unknown: return "?"
        }
    }

    /// Pure, tested: hides network names, MAC addresses and private/link-local IPv4 addresses.
    public static func mask(_ text: String, names: [String]) -> String {
        var out = text
        for name in Set(names).filter({ !$0.isEmpty }).sorted(by: { $0.count > $1.count }) {
            out = out.replacingOccurrences(of: name, with: "‹network›")
        }
        let patterns = [
            #"\b[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}\b"#: "‹hw-id›",
            #"\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01])|169\.254)\.\d{1,3}\.\d{1,3}\b"#: "‹local›",
        ]
        for (pattern, replacement) in patterns {
            out = out.replacingOccurrences(of: pattern, with: replacement, options: .regularExpression)
        }
        return out
    }
}
