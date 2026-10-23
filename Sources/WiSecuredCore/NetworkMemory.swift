import Foundation

/// Phase 2: networks WiSecured has seen, kept only on this Mac. A network's fingerprint is its
/// Wi-Fi name plus its router's hardware address (several access points of one mesh share the
/// router; a chain café's branches have different routers, so they stay separate networks).
public struct RememberedNetwork: Codable, Sendable, Identifiable, Equatable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case automatic, trusted, office, hotspot, publicNetwork

        public var label: String {
            switch self {
            case .automatic: return "Automatic"
            case .trusted: return "Trusted"
            case .office: return "Office"
            case .hotspot: return "Phone hotspot"
            case .publicNetwork: return "Public"
            }
        }
        /// Trusted and Office both count as networks you control (or your employer does).
        public var isTrustedLike: Bool { self == .trusted || self == .office }
    }

    public var id: UUID
    /// nil for a wired network.
    public var ssid: String?
    public var routerIP: String?
    public var routerMACs: [String]
    public var accessPoints: [String]
    /// Strongest Wi-Fi security seen on this network (see `NetworkMemory.securityRank`).
    public var strongestSecurityRank: Int?
    public var lastSecurity: String?
    public var kind: Kind
    public var firstSeen: Date
    public var lastSeen: Date
    public var timesSeen: Int

    public var displayName: String { ssid ?? "Wired network" }
}

/// How the current network relates to what's remembered.
public enum MemoryMatch: Sendable, Equatable {
    /// Seen before (same name and the same router, or the same access point).
    case known(RememberedNetwork)
    /// Not seen before. `sameName` = this name was seen with another router; `trustedName` = one
    /// of those was trusted.
    case new(sameName: Bool, trustedName: Bool, rememberedRouters: [String])
}

public struct MemoryReading: Sendable, Equatable {
    public var isWiFi: Bool
    public var ssid: String?
    public var routerMAC: String?
    public var securityRaw: Int?
    public var security: String
    public var match: MemoryMatch
    /// Strongest security ever seen for this Wi-Fi name (any router).
    public var strongestRankForName: Int?
    public var strongestNameSecurity: String?

    public init(isWiFi: Bool, ssid: String?, routerMAC: String?, securityRaw: Int?, security: String,
                match: MemoryMatch, strongestRankForName: Int?, strongestNameSecurity: String?) {
        self.isWiFi = isWiFi; self.ssid = ssid; self.routerMAC = routerMAC; self.securityRaw = securityRaw
        self.security = security; self.match = match
        self.strongestRankForName = strongestRankForName; self.strongestNameSecurity = strongestNameSecurity
    }
}

public enum NetworkMemory {
    /// CWSecurity raw value → strength: 0 open, 1 broken (WEP), 2 encrypted without a password
    /// (OWE) or old WPA, 3 WPA/WPA2 mixed, 4 WPA2 / generic, 5 WPA3.
    public static func securityRank(_ raw: Int?) -> Int? {
        guard let raw, raw >= 0, raw < 1000 else { return nil }
        switch raw {
        case 0: return 0
        case 1, 6: return 1
        case 2, 7, 14, 15: return 2
        case 3, 8: return 3
        case 11, 12: return 5
        default: return 4
        }
    }

    /// Pure: compares the current network with the remembered ones.
    public static func assess(_ context: NetworkContext, records: [RememberedNetwork]) -> MemoryReading {
        let sameName = records.filter { $0.ssid == context.ssid }
        var match: MemoryMatch
        if let found = sameName.first(where: { record in
            (context.routerMAC.map { record.routerMACs.contains($0) } ?? false)
                || (context.bssid.map { record.accessPoints.contains($0) } ?? false)
        }) {
            match = .known(found)
        } else {
            match = .new(sameName: !sameName.isEmpty,
                         trustedName: sameName.contains { $0.kind.isTrustedLike },
                         rememberedRouters: sameName.flatMap(\.routerMACs))
        }
        let strongest = sameName.max { ($0.strongestSecurityRank ?? -1) < ($1.strongestSecurityRank ?? -1) }
        return MemoryReading(isWiFi: context.isWiFi, ssid: context.ssid, routerMAC: context.routerMAC,
                             securityRaw: context.securityRaw, security: context.security, match: match,
                             strongestRankForName: context.isWiFi ? strongest?.strongestSecurityRank : nil,
                             strongestNameSecurity: strongest?.lastSecurity)
    }

    /// Pure: the records after seeing `context` once more (new network added, or the known one
    /// updated with this visit, a new access point / router address, the strongest security).
    /// The remembered record for the network in `context`, if it's a known one.
    public static func record(for context: NetworkContext, in records: [RememberedNetwork]) -> RememberedNetwork? {
        if case .known(let record) = assess(context, records: records).match { return record }
        return nil
    }

    public static func remembering(_ context: NetworkContext, in records: [RememberedNetwork], at date: Date = Date()) -> [RememberedNetwork] {
        guard context.routerMAC != nil || context.ssid != nil else { return records }
        var updated = records
        let rank = context.isWiFi ? securityRank(context.securityRaw) : nil
        if case .known(let found) = assess(context, records: records).match, let index = updated.firstIndex(where: { $0.id == found.id }) {
            var record = updated[index]
            if let mac = context.routerMAC, !record.routerMACs.contains(mac) { record.routerMACs.append(mac) }
            if let ap = context.bssid, !record.accessPoints.contains(ap) { record.accessPoints.append(ap) }
            if let rank, rank > (record.strongestSecurityRank ?? -1) {
                record.strongestSecurityRank = rank
                record.lastSecurity = context.security
            }
            record.routerIP = context.router ?? record.routerIP
            record.lastSeen = date
            record.timesSeen += 1
            updated[index] = record
        } else {
            updated.append(RememberedNetwork(
                id: UUID(), ssid: context.isWiFi ? context.ssid : nil, routerIP: context.router,
                routerMACs: context.routerMAC.map { [$0] } ?? [], accessPoints: context.bssid.map { [$0] } ?? [],
                strongestSecurityRank: rank, lastSecurity: context.isWiFi ? context.security : nil,
                kind: context.isExpensive ? .hotspot : .automatic,
                firstSeen: date, lastSeen: date, timesSeen: 1))
        }
        return updated
    }
}

/// Saves the remembered networks as JSON in this app's own Application Support folder
/// (owner-only). Nothing leaves the Mac.
public final class NetworkMemoryFile {
    public let url: URL

    public init(bundleID: String) {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        url = base.appendingPathComponent(bundleID, isDirectory: true).appendingPathComponent("networks.json")
    }

    public func load() -> [RememberedNetwork] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([RememberedNetwork].self, from: data)) ?? []
    }

    public func save(_ records: [RememberedNetwork]) {
        let folder = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(records) else { return }
        try? data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
