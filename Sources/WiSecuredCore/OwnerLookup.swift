import Foundation
import Network

/// Who an internet address is registered to (from the regional internet registry, RDAP).
public struct OwnerInfo: Sendable, Equatable, Codable {
    public var address: String
    /// Best human name: the registry's description, else the organisation, e.g. "Sky UK Limited".
    public var label: String
    /// The registry's network name, e.g. "SKY-BROADBAND".
    public var network: String?
    public var country: String?
    /// Organisation / role handles directly on the network (registrant, admin, tech, abuse).
    public var handles: Set<String>
    /// Domains of the abuse contacts' e-mail addresses (free-mail domains left out).
    public var abuseDomains: Set<String>
    public var registry: String

    public init(address: String, label: String, network: String? = nil, country: String? = nil,
                handles: Set<String> = [], abuseDomains: Set<String> = [], registry: String = "") {
        self.address = address; self.label = label; self.network = network; self.country = country
        self.handles = handles; self.abuseDomains = abuseDomains; self.registry = registry
    }

    public var labelWithCountry: String { label + (country.map { ", \($0)" } ?? "") }
}

/// Registry lookups (pure parts, testable without the network).
public enum Owners {
    public enum Registry: String, CaseIterable, Sendable {
        case afrinic, apnic, arin, lacnic, ripe

        public var name: String {
            switch self {
            case .afrinic: return "AFRINIC"
            case .apnic: return "APNIC"
            case .arin: return "ARIN"
            case .lacnic: return "LACNIC"
            case .ripe: return "RIPE NCC"
            }
        }
        public var host: String {
            switch self {
            case .afrinic: return "rdap.afrinic.net"
            case .apnic: return "rdap.apnic.net"
            case .arin: return "rdap.arin.net"
            case .lacnic: return "rdap.lacnic.net"
            case .ripe: return "rdap.db.ripe.net"
            }
        }
        public var ipPath: String {
            switch self {
            case .afrinic, .lacnic: return "/rdap/ip/"
            case .arin: return "/registry/ip/"
            case .apnic, .ripe: return "/ip/"
            }
        }
    }

    /// IANA's RDAP bootstrap for IPv4 (data.iana.org/rdap/ipv4.json, every entry a /8; fetched
    /// 2026-10-23). Ranges not listed are asked at ARIN, which points to the right registry.
    static let firstOctets: [Registry: Set<UInt8>] = [
        .afrinic: [41, 102, 105, 154, 196, 197],
        .apnic: [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 133, 150, 153, 163, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223],
        .arin: [3, 4, 6, 7, 8, 9, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 28, 29, 30, 32, 33, 34, 35, 38, 40, 44, 45, 47, 48, 50, 52, 54, 55, 56, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 128, 129, 130, 131, 132, 134, 135, 136, 137, 138, 139, 140, 142, 143, 144, 146, 147, 148, 149, 152, 155, 156, 157, 158, 159, 160, 161, 162, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 214, 215, 216],
        .ripe: [2, 5, 25, 31, 37, 46, 51, 53, 57, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217],
        .lacnic: [177, 179, 181, 186, 187, 189, 190, 191, 200, 201],
    ]

    /// A public, routable IPv4 address (not private, loopback, link-local, shared CGNAT, test or multicast).
    public static func isPublicIPv4(_ ip: String) -> Bool {
        guard let v = Checks.ipv4(ip) else { return false }
        let a = v >> 24, b = (v >> 16) & 0xff
        if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
        if a == 100 && (64...127).contains(b) { return false }          // shared address space (CGNAT, Tailscale)
        if a == 169 && b == 254 { return false }
        if a == 172 && (16...31).contains(b) { return false }
        if a == 192 && b == 168 { return false }
        if a == 192 && b == 0 && ((v >> 8) & 0xff) == 2 { return false } // TEST-NET-1
        if a == 198 && (b == 18 || b == 19) { return false }
        return true
    }

    public static func registry(for ip: String) -> Registry? {
        guard isPublicIPv4(ip), let v = Checks.ipv4(ip) else { return nil }
        let first = UInt8(v >> 24)
        return Registry.allCases.first { firstOctets[$0]?.contains(first) == true } ?? .arin
    }

    /// Hosts a lookup may be redirected to (only the five registries).
    static func isRegistryHost(_ host: String) -> Bool { Registry.allCases.contains { $0.host == host } }

    static let freeMail: Set<String> = ["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
                                        "proton.me", "protonmail.com", "mail.ru", "yandex.ru", "qq.com", "163.com", "126.com", "icloud.com"]

    /// Reads an RDAP "ip network" answer.
    public static func parseRDAP(_ data: Data, address: String, registry: String) -> OwnerInfo? {
        guard let d = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let network = d["name"] as? String
        let country = d["country"] as? String
        var description: String?
        for remark in d["remarks"] as? [[String: Any]] ?? [] {
            let title = (remark["title"] as? String ?? "").lowercased()
            if title == "description" || title.isEmpty, let lines = remark["description"] as? [String], let first = lines.first, !first.isEmpty {
                description = first; break
            }
        }
        var handles = Set<String>(), abuse = Set<String>()
        var byRole: [String: String] = [:]
        for entity in d["entities"] as? [[String: Any]] ?? [] {
            let roles = entity["roles"] as? [String] ?? []
            if let handle = entity["handle"] as? String, !handle.uppercased().hasPrefix("RIPE-NCC") { handles.insert(handle.uppercased()) }
            var fn: String?, emails: [String] = []
            if let vcard = entity["vcardArray"] as? [Any], vcard.count > 1, let items = vcard[1] as? [[Any]] {
                for item in items where item.count > 3 {
                    if item[0] as? String == "fn" { fn = item[3] as? String }
                    if item[0] as? String == "email", let mail = item[3] as? String { emails.append(mail) }
                }
            }
            if roles.contains("abuse") {
                for mail in emails {
                    if let domain = mail.split(separator: "@").last.map({ String($0).lowercased() }), !freeMail.contains(domain) { abuse.insert(domain) }
                }
            }
            if let fn, !looksLikeHandle(fn) {
                for role in roles where byRole[role] == nil { byRole[role] = fn }
            }
        }
        let label = description ?? byRole["registrant"] ?? byRole["administrative"] ?? byRole["technical"]
            ?? byRole["abuse"].flatMap { $0.lowercased().contains("abuse") ? nil : $0 } ?? network ?? "Unknown owner"
        return OwnerInfo(address: address, label: label, network: network, country: country,
                         handles: handles, abuseDomains: abuse, registry: registry)
    }

    /// "BSKYB-BROADBAND-MNT", "ORG-ABC1-RIPE", "mnt-us-example-1" — a registry handle, not a readable name.
    static func looksLikeHandle(_ text: String) -> Bool {
        !text.contains(" ") && text.contains("-")
    }

    /// The same organisation: a shared handle (organisation, role, maintainer) or the same abuse
    /// mail domain — registry facts, not a guess from similar-looking names.
    public static func sameProvider(_ a: OwnerInfo, _ b: OwnerInfo) -> Bool {
        if !a.handles.isDisjoint(with: b.handles) { return true }
        if !a.abuseDomains.isDisjoint(with: b.abuseDomains) { return true }
        return false
    }
}

/// Network side of the owner lookups, with a cache (answers kept for a day, failures for 5 min).
/// Every request is HTTPS straight to the registry (or 1.1.1.1 for the public address), with
/// Apple's built-in certificate authorities only (`NetIO.httpsGet`).
public actor OwnerLookup {
    public static let shared = OwnerLookup()

    private var owners: [String: (info: OwnerInfo?, at: Date)] = [:]
    private var publicAddresses: [String: (ip: String?, at: Date)] = [:]

    /// Cached owner only (no request).
    public func cached(_ ip: String) -> OwnerInfo? { owners[ip]?.info }

    public func owner(of ip: String, refresh: Bool = false) async -> OwnerInfo? {
        if !refresh, let hit = owners[ip] {
            let age = Date().timeIntervalSince(hit.at)
            if hit.info != nil ? age < 86_400 : age < 300 { return hit.info }
        }
        let info = await Self.fetch(ip)
        owners[ip] = (info, Date())
        return info
    }

    public func owners(of ips: [String], refresh: Bool = false) async -> [String: OwnerInfo] {
        var result: [String: OwnerInfo] = [:]
        for ip in ips where Owners.isPublicIPv4(ip) {
            if let info = await owner(of: ip, refresh: refresh) { result[ip] = info }
        }
        return result
    }

    /// This network's internet provider: its public address (over the network itself, not a VPN),
    /// then that address's owner. `key` = the network (address cached 30 min per network).
    public func provider(key: String, via interfaceType: NWInterface.InterfaceType?, refresh: Bool = false) async -> OwnerInfo? {
        var ip: String?
        if !refresh, let hit = publicAddresses[key], Date().timeIntervalSince(hit.at) < 1800 {
            ip = hit.ip
        } else {
            ip = await Self.publicIPv4(via: interfaceType)
            publicAddresses[key] = (ip, Date())
        }
        guard let ip else { return nil }
        return await owner(of: ip, refresh: refresh)
    }

    /// Cached provider only (no request).
    public func cachedProvider(key: String) -> OwnerInfo? {
        guard let ip = publicAddresses[key]?.ip else { return nil }
        return owners[ip]?.info
    }

    /// The network's public IPv4 address, from Cloudflare's trace page at 1.1.1.1 (by IP, the
    /// certificate is valid for it). Your registry already sees this address on every connection.
    static func publicIPv4(via interfaceType: NWInterface.InterfaceType?) async -> String? {
        guard let r = await NetIO.httpsGet(host: "1.1.1.1", path: "/cdn-cgi/trace", via: interfaceType), r.status == 200 else { return nil }
        for line in r.body.split(separator: "\n") where line.hasPrefix("ip=") {
            let ip = String(line.dropFirst(3))
            return Owners.isPublicIPv4(ip) ? ip : nil
        }
        return nil
    }

    static func fetch(_ ip: String) async -> OwnerInfo? {
        guard let registry = Owners.registry(for: ip) else { return nil }
        var host = registry.host, path = registry.ipPath + ip
        for _ in 0..<3 {   // the first answer, or up to two redirects between registries
            guard let r = await NetIO.httpsGet(host: host, path: path, accept: "application/rdap+json") else { return nil }
            if r.status == 200 {
                let name = Owners.Registry.allCases.first { $0.host == host }?.name ?? host
                return Owners.parseRDAP(r.data, address: ip, registry: name)
            }
            guard (300...399).contains(r.status), let location = r.headers["location"], let url = URL(string: location),
                  url.scheme == "https", let next = url.host, Owners.isRegistryHost(next) else { return nil }
            host = next
            path = url.path
        }
        return nil
    }
}
