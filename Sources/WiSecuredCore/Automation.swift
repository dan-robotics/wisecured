import Foundation

// 0.5.0: the two things WiSecured may change — only when the user switches them on (both off by
// default). The decisions are pure (tested); the changes go through macOS' own `networksetup`,
// run as the user with fixed arguments (no shell), exactly like a DNS switcher script would.

/// L5 "DNS rules": the DNS the user wants on one remembered network.
public enum DNSRule: Codable, Sendable, Equatable {
    /// Whatever the network hands out (or Secure DNS, if its profile is installed).
    case network
    /// Fixed addresses, e.g. a Pi-hole at home.
    case custom([String])

    /// What `networksetup -setdnsservers` should end up with ([] = the network's, "Empty").
    public var servers: [String] {
        if case .custom(let list) = self { return list }
        return []
    }
}

/// Proxy Auto (S1): the proxy the user typed in Settings, on only where it can work.
public enum ProxyMode: String, Codable, Sendable, CaseIterable {
    case notManaged, auto, off

    public var label: String {
        switch self {
        case .notManaged: return "Not managed (default)"
        case .auto: return "Auto — on Office networks or while a work VPN is up"
        case .off: return "Off everywhere"
        }
    }
}

public enum Automation {
    /// The DNS a network should have under DNS rules (unlisted networks: the network's own).
    public static func desiredDNS(record: RememberedNetwork?, rules: [UUID: DNSRule]) -> [String] {
        guard let record, let rule = rules[record.id] else { return [] }
        return rule.servers
    }

    /// Order doesn't matter; an empty list means "the network's".
    public static func dnsDiffers(current: [String], desired: [String]) -> Bool {
        Set(current) != Set(desired)
    }

    /// Valid IPv4/IPv6 addresses only (anything else is dropped before reaching networksetup).
    public static func validAddresses(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" }).map(String.init).filter(isAddress)
    }

    public static func isAddress(_ text: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, text, &v4) == 1 || inet_pton(AF_INET6, text, &v6) == 1
    }

    /// A work VPN is up: a tunnel interface with an IPv4 address outside 100.64.0.0/10 (that range
    /// is Tailscale's, which doesn't reach an office proxy).
    public static func workVPNUp(vpnInterfaces: [String], ipv4: [String: (address: String, mask: String)]) -> Bool {
        vpnInterfaces.contains { name in
            guard let address = ipv4[name]?.address, let v = Checks.ipv4(address) else { return false }
            return !(v >> 24 == 100 && (64...127).contains((v >> 16) & 0xff))
        }
    }

    /// Proxy Auto: on for Office networks or while a work VPN is up; off everywhere else.
    public static func proxyWanted(mode: ProxyMode, kind: RememberedNetwork.Kind?, workVPN: Bool) -> Bool? {
        switch mode {
        case .notManaged: return nil
        case .off: return false
        case .auto: return kind == .office || workVPN
        }
    }

    /// Whether the proxy `host:port` is on right now (web or secure web).
    public static func proxyIsOn(host: String, port: Int, entries: [Checks.ProxyEntry]) -> Bool {
        entries.contains { $0.host == host && $0.port == port && $0.kind != "SOCKS proxy" }
    }
}

/// Changes through macOS' `networksetup` (as the user, fixed arguments, no shell).
public enum NetworkSetup {
    static let tool = "/usr/sbin/networksetup"

    /// The network service name ("Wi-Fi", "USB 10/100/1000 LAN") for an interface ("en0").
    public static func serviceName(forInterface name: String) -> String? {
        let text = NetworkReader.run(tool, ["-listallhardwareports"])
        var port: String?
        for line in text.split(separator: "\n") {
            if line.hasPrefix("Hardware Port: ") { port = String(line.dropFirst("Hardware Port: ".count)) }
            if line.hasPrefix("Device: "), String(line.dropFirst("Device: ".count)) == name { return port }
        }
        return nil
    }

    /// Returns nil on success, otherwise what went wrong.
    public static func setDNS(_ servers: [String], service: String) -> String? {
        let list = servers.filter(Automation.isAddress)
        return check(NetworkReader.runDetailed(tool, ["-setdnsservers", service] + (list.isEmpty ? ["Empty"] : list)))
    }

    public static func setProxy(host: String, port: Int, on: Bool, service: String) -> String? {
        if on {
            guard !host.isEmpty, host.allSatisfy({ $0.isLetter || $0.isNumber || ".-:".contains($0) }), (1...65535).contains(port) else {
                return "the proxy address or port isn't valid"
            }
            if let error = check(NetworkReader.runDetailed(tool, ["-setwebproxy", service, host, String(port)])) { return error }
            return check(NetworkReader.runDetailed(tool, ["-setsecurewebproxy", service, host, String(port)]))
        }
        if let error = check(NetworkReader.runDetailed(tool, ["-setwebproxystate", service, "off"])) { return error }
        return check(NetworkReader.runDetailed(tool, ["-setsecurewebproxystate", service, "off"]))
    }

    static func check(_ result: (output: String, status: Int32)) -> String? {
        let text = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        if result.status != 0 || text.lowercased().contains("error") || text.lowercased().contains("requires admin") {
            return text.isEmpty ? "networksetup failed (\(result.status))" : text
        }
        return nil
    }
}
