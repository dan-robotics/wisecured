import Foundation

/// How one check came out. Ordered by severity for the verdict (unknown = could not run).
public enum CheckStatus: Int, Sendable, Comparable, Codable {
    case ok, info, warn, danger, unknown

    public static func < (a: CheckStatus, b: CheckStatus) -> Bool { a.rawValue < b.rawValue }
}

/// The ten checks, in the order the dropdown shows them.
public enum CheckID: String, CaseIterable, Sendable, Codable {
    case captivePortal, dnsInterception, dnsAnswers, dnssec, certificates,
         routerIdentity, networkDNS, pageIntegrity, wifiSecurity, routingHealth

    public var title: String {
        switch self {
        case .captivePortal: return "Captive portal"
        case .dnsInterception: return "DNS interception"
        case .dnsAnswers: return "DNS answers"
        case .dnssec: return "DNSSEC"
        case .certificates: return "Certificates"
        case .routerIdentity: return "Router identity"
        case .networkDNS: return "Network DNS server"
        case .pageIntegrity: return "Page integrity"
        case .wifiSecurity: return "Wi-Fi security"
        case .routingHealth: return "Routing health"
        }
    }
}

/// One check's result in plain language: what was seen, what it most likely means (including
/// the harmless explanation when there is one) and what to do.
public struct Finding: Sendable, Identifiable, Equatable {
    public var id: CheckID
    public var status: CheckStatus
    /// Short result for the dropdown row, e.g. "Match Quad9".
    public var summary: String
    public var seen: String
    public var meaning: String
    public var action: String

    public init(_ id: CheckID, _ status: CheckStatus, summary: String, seen: String, meaning: String, action: String = "") {
        self.id = id
        self.status = status
        self.summary = summary
        self.seen = seen
        self.meaning = meaning
        self.action = action
    }
}

public enum Verdict: Sendable, Equatable {
    case safe, careful, danger, checking, offline

    public var title: String {
        switch self {
        case .safe: return "Looks safe"
        case .careful: return "Be careful"
        case .danger: return "Don't trust this network"
        case .checking: return "Checking…"
        case .offline: return "No network"
        }
    }
}

/// What the Mac's own connection looks like right now (all read locally).
public struct NetworkContext: Sendable, Equatable {
    public var interfaceName: String?
    public var isWiFi: Bool
    public var ssid: String?
    public var bssid: String?
    public var securityRaw: Int?
    public var security: String
    public var isExpensive: Bool
    public var router: String?
    public var routerMAC: String?
    public var otherIPsWithRouterMAC: [String]
    /// DNS servers the Mac actually uses right now (what lookups go to).
    public var dnsServers: [String]
    /// DNS servers the network handed out (DHCP) for the physical interface.
    public var dnsFromNetwork: [String]
    /// DNS servers set by hand on this Mac for that interface (System Settings or a script).
    public var dnsSetOnMac: [String]
    /// Tunnel interfaces that carry routes (utun/ppp/ipsec), e.g. corporate VPN clients, Tailscale.
    public var vpnInterfaces: [String]
    /// Interface the default route uses (a utun here means a full-tunnel VPN).
    public var defaultRouteInterface: String?

    public init(interfaceName: String? = nil, isWiFi: Bool = false, ssid: String? = nil, bssid: String? = nil,
                securityRaw: Int? = nil, security: String = "unknown", isExpensive: Bool = false,
                router: String? = nil, routerMAC: String? = nil, otherIPsWithRouterMAC: [String] = [],
                dnsServers: [String] = [], dnsFromNetwork: [String] = [], dnsSetOnMac: [String] = [], vpnInterfaces: [String] = [], defaultRouteInterface: String? = nil) {
        self.interfaceName = interfaceName
        self.isWiFi = isWiFi
        self.ssid = ssid
        self.bssid = bssid
        self.securityRaw = securityRaw
        self.security = security
        self.isExpensive = isExpensive
        self.router = router
        self.routerMAC = routerMAC
        self.otherIPsWithRouterMAC = otherIPsWithRouterMAC
        self.dnsServers = dnsServers
        self.dnsFromNetwork = dnsFromNetwork
        self.dnsSetOnMac = dnsSetOnMac
        self.vpnInterfaces = vpnInterfaces
        self.defaultRouteInterface = defaultRouteInterface
    }

    public var vpnOn: Bool { !vpnInterfaces.isEmpty }
    public var displayName: String { ssid ?? (isWiFi ? "Wi-Fi (name hidden)" : (interfaceName ?? "Network")) }
}

/// One full check: the network, every finding and the overall verdict.
public struct Report: Sendable {
    public var date: Date
    public var network: NetworkContext
    public var findings: [Finding]
    public var verdict: Verdict
    /// One or two sentences under the verdict.
    public var reason: String

    public init(date: Date, network: NetworkContext, findings: [Finding], verdict: Verdict, reason: String) {
        self.date = date
        self.network = network
        self.findings = findings
        self.verdict = verdict
        self.reason = reason
    }

    public func finding(_ id: CheckID) -> Finding? { findings.first { $0.id == id } }
}
