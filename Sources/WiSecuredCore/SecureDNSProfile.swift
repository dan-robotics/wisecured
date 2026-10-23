import Foundation

/// P5 "Secure my DNS": an encrypted-DNS configuration profile (Apple's DNS Settings payload,
/// com.apple.dnsSettings.managed, DNS over HTTPS). WiSecured only writes the file; macOS asks the
/// user to approve it in System Settings, and it's removed there too. Off until the user installs it.
public enum SecureDNSProfile {
    /// Same identifier every time, so a new profile replaces the old one instead of piling up.
    public static func identifier(bundleID: String) -> String { "\(bundleID).secure-dns" }

    /// - Parameters:
    ///   - skipNetworks: Wi-Fi names where the profile stays off (e.g. home with a Pi-hole).
    ///   - skipDomains: names that keep using the network's / VPN's DNS (e.g. a company domain).
    public static func make(provider: Checker.Reference, skipNetworks: [String], skipDomains: [String], bundleID: String) -> Data {
        let base = identifier(bundleID: bundleID)
        var rules: [[String: Any]] = []
        let networks = clean(skipNetworks)
        if !networks.isEmpty { rules.append(["Action": "Disconnect", "SSIDMatch": networks]) }
        let domains = clean(skipDomains).map { $0.hasPrefix("*.") ? String($0.dropFirst(2)) : $0 }
        if !domains.isEmpty {
            rules.append(["Action": "EvaluateConnection",
                          "ActionParameters": [["DomainAction": "NeverConnect", "Domains": domains]]])
        }
        rules.append(["Action": "Connect"])

        let dns: [String: Any] = [
            "PayloadType": "com.apple.dnsSettings.managed",
            "PayloadVersion": 1,
            "PayloadIdentifier": "\(base).dns",
            "PayloadUUID": UUID().uuidString,
            "PayloadDisplayName": "Encrypted DNS — \(provider.name)",
            "DNSSettings": [
                "DNSProtocol": "HTTPS",
                "ServerURL": provider.profileURL,
                "ServerAddresses": [provider.address, provider.secondaryDNS],
            ],
            "OnDemandRules": rules,
            "ProhibitDisablement": false,
        ]
        let profile: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": base,
            "PayloadUUID": UUID().uuidString,
            "PayloadDisplayName": "WiSecured — Secure DNS (\(provider.name))",
            "PayloadDescription": "Encrypts this Mac's DNS with \(provider.name) (\(provider.profileURL))."
                + (networks.isEmpty ? "" : " Off on: \(networks.joined(separator: ", ")).")
                + " Created by WiSecured; remove it any time in System Settings.",
            "PayloadOrganization": "WiSecured",
            "PayloadScope": "System",
            "PayloadRemovalDisallowed": false,
            "PayloadContent": [dns],
        ]
        return (try? PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)) ?? Data()
    }

    static func clean(_ list: [String]) -> [String] {
        var seen = Set<String>()
        return list.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    /// "corp.example, intranet.local" → ["corp.example", "intranet.local"]
    public static func domains(from text: String) -> [String] {
        clean(text.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" }).map(String.init))
    }
}
