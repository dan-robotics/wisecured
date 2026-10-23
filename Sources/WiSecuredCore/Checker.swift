import Foundation
import Network

/// Runs the twelve checks against the current network and returns one Report. Read-only: it reads
/// local state and sends test questions (plus owner lookups when switched on); it never changes a
/// setting or a route.
public struct Checker: Sendable {
    /// The encrypted-DNS reference (Settings › Compare DNS with) — also the provider "Secure my DNS"
    /// installs. Each falls back to Quad9 / Cloudflare / Google. Every one was tested 2026-10-23:
    /// DoH by IP with a valid certificate, and DNSSEC validation (dnssec-failed.org → SERVFAIL).
    public enum Reference: String, Sendable, CaseIterable, Codable {
        case quad9, cloudflare, google, adguard, dns4eu

        public var name: String {
            switch self {
            case .quad9: return "Quad9"
            case .cloudflare: return "Cloudflare"
            case .google: return "Google"
            case .adguard: return "AdGuard"
            case .dns4eu: return "DNS4EU"
            }
        }
        /// What the service adds, for Settings.
        public var features: String {
            switch self {
            case .quad9: return "threat blocking + DNSSEC, Switzerland"
            case .cloudflare: return "malware blocking + DNSSEC"
            case .google: return "DNSSEC"
            case .adguard: return "ad + tracker blocking + DNSSEC, Cyprus"
            case .dns4eu: return "threat blocking + DNSSEC, EU (protective)"
            }
        }
        public var address: String { plainDNS }
        var doh: URL { URL(string: "https://\(plainDNS)/dns-query")! }
        /// DNS4EU's certificate names its hosts but not its IPs: it's reached by IP and its
        /// certificate checked against this name instead (just as strict).
        var dohCertificateName: String? { self == .dns4eu ? "protective.joindns4.eu" : nil }
        var plainDNS: String {
            switch self {
            case .quad9: return "9.9.9.9"
            case .cloudflare: return "1.1.1.2"
            case .google: return "8.8.8.8"
            case .adguard: return "94.140.14.14"
            case .dns4eu: return "86.54.11.1"
            }
        }
        public var secondaryDNS: String {
            switch self {
            case .quad9: return "149.112.112.112"
            case .cloudflare: return "1.0.0.2"
            case .google: return "8.8.4.4"
            case .adguard: return "94.140.15.15"
            case .dns4eu: return "86.54.11.201"
            }
        }
        /// The encrypted-DNS address the Secure DNS profile uses (the profile also lists the IPs,
        /// so a filter blocking these names doesn't matter).
        public var profileURL: String {
            switch self {
            case .quad9: return "https://dns.quad9.net/dns-query"
            case .cloudflare: return "https://security.cloudflare-dns.com/dns-query"
            case .google: return "https://dns.google/dns-query"
            case .adguard: return "https://dns.adguard-dns.com/dns-query"
            case .dns4eu: return "https://protective.joindns4.eu/dns-query"
            }
        }
        /// This one first, then Quad9 → Cloudflare → Google.
        public var fallbackOrder: [Reference] { [self] + [Reference.quad9, .cloudflare, .google].filter { $0 != self } }
    }

    public var reference: Reference
    /// Owner lookups (registry, over HTTPS): your provider + any rewritten address. Settings.
    public var lookups: Bool
    /// Filter devices the user confirmed (option D).
    public var filterDevices: [FilterDevice]

    public init(reference: Reference = .quad9, lookups: Bool = false, filterDevices: [FilterDevice] = []) {
        self.reference = reference
        self.lookups = lookups
        self.filterDevices = filterDevices
    }

    // MARK: Local readings (instant)

    /// The connection as the Mac sees it. `physical` = the Wi-Fi/Ethernet interface the path uses.
    public func context(physical: (name: String, isWiFi: Bool)?, isExpensive: Bool) -> NetworkContext {
        let wifi = NetworkReader.wifi()
        let routes = NetworkReader.routes()
        let defaultRoute = routes.first { $0.isDefault && !$0.isScoped }
        let routerRoute = routes.first { $0.isDefault && $0.interface == physical?.name && $0.gatewayIsAddress }
        let router = routerRoute?.gateway
        let identity = NetworkReader.routerIdentity(router: router)
        let onWiFi = physical?.isWiFi ?? false
        return NetworkContext(
            interfaceName: physical?.name, isWiFi: onWiFi,
            ssid: onWiFi ? wifi.ssid : nil, bssid: onWiFi ? wifi.bssid : nil,
            securityRaw: onWiFi ? NetworkReader.securityRaw() : nil, security: onWiFi ? wifi.security : "Wired",
            isExpensive: isExpensive, router: router, routerMAC: identity.mac, otherIPsWithRouterMAC: identity.others,
            dnsServers: NetworkReader.dnsServers(), dnsFromNetwork: NetworkReader.dnsServers(forInterface: physical?.name),
            dnsSetOnMac: NetworkReader.dnsSetOnMac(forInterface: physical?.name),
            vpnInterfaces: NetworkReader.vpnInterfaces(in: routes), defaultRouteInterface: defaultRoute?.interface)
    }

    /// The light 5-second watch: only the router's identity.
    public func routerFinding(_ context: NetworkContext, previousMAC: String?) -> Finding {
        Checks.routerIdentity(router: context.router, mac: context.routerMAC, otherIPs: context.otherIPsWithRouterMAC, previousMAC: previousMAC)
    }

    // MARK: Full check

    /// `memory` = the networks remembered on this Mac (phase 2), for the "Known network" check.
    /// `networkKey` = this network's key (caches the provider lookup per network).
    public func run(physical: (name: String, isWiFi: Bool)?, isExpensive: Bool, previousRouterMAC: String?,
                    memory: [RememberedNetwork] = [], networkKey: String = "") async -> Report {
        let context = context(physical: physical, isExpensive: isExpensive)
        guard physical != nil else {
            let decided = VerdictRules.decide([], network: context, connected: false)
            return Report(date: Date(), network: context, findings: [], verdict: decided.verdict, reason: decided.reason)
        }
        let via: NWInterface.InterfaceType = context.isWiFi ? .wifi : .wiredEthernet
        let record = NetworkMemory.record(for: context, in: memory)
        let trusted = record?.kind.isTrustedLike ?? false
        let lookups = self.lookups

        async let apple = NetIO.httpGet(host: "captive.apple.com", path: "/hotspot-detect.html", via: via)
        async let firefox = NetIO.httpGet(host: "detectportal.firefox.com", path: "/success.txt", via: via)
        async let upgrade = NetIO.httpGet(host: "www.apple.com", path: "/", via: via)
        async let testNet = NetIO.dns(server: Checks.testNetDNS, name: "one.one.one.one", via: via, timeout: 2)
        async let dnssec = NetIO.dns(server: reference.plainDNS, name: Checks.dnssecBrokenName, via: via, timeout: 4)
        async let anchors = dnsAnswerReadings(context, via: via)
        async let certs = certReadings(via: via)
        async let offNetwork = offNetworkReading(context)
        async let provider: OwnerInfo? = lookups
            ? OwnerLookup.shared.provider(key: networkKey, via: via)
            : OwnerLookup.shared.cachedProvider(key: networkKey)

        let appleResult = await apple
        let upgradeResult = await upgrade
        let upgradeKept: Bool? = upgradeResult.map { r in
            (300...399).contains(r.status) && (r.headers["location"]?.lowercased().hasPrefix("https://") ?? false)
        }
        let routing = routingReading(context)

        // Evidence for rewritten answers: who owns them, and which local devices are confirmed filters.
        let answers = await anchors
        let rewritten = Checks.rewrittenAddresses(answers.readings)
        let publicRewrites = rewritten.filter(Owners.isPublicIPv4)
        var owners: [String: OwnerInfo] = [:]
        if lookups {
            owners = await OwnerLookup.shared.owners(of: publicRewrites)
        } else {
            for ip in publicRewrites { if let hit = await OwnerLookup.shared.cached(ip) { owners[ip] = hit } }
        }
        let localAddresses = (rewritten + [answers.server].compactMap { $0 } + context.dnsSetOnMac + context.dnsFromNetwork)
            .filter(Checks.isPrivate).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
        let table = NetworkReader.directAddressTable().entries
        var devices: [String: FilterMatch] = [:]
        for address in localAddresses {
            let mac = table.first { $0.ip == address }?.mac
            devices[address] = FilterDevices.match(address: address, mac: mac, network: record, devices: filterDevices)
        }
        let candidate = localAddresses.first { address in
            devices[address] == .unconfirmed && address != context.router && table.contains { $0.ip == address }
        }.flatMap { address in table.first { $0.ip == address }.map { LocalDevice(address: address, mac: $0.mac) } }
        let ownProvider = await provider
        let evidence = Checks.DNSEvidence(trustedNetwork: trusted, provider: ownProvider, owners: owners, devices: devices, lookupsOn: lookups)

        let findings: [Finding] = [
            Checks.captivePortal(.init(body: appleResult?.body, error: appleResult == nil ? "no answer" : nil)),
            Checks.dnsInterception(testNetAnswered: (await testNet).answered),
            Checks.dnsAnswers(answers.readings, referenceName: reference.name, server: answers.server,
                              fallback: answers.fallback, vpnOn: context.vpnOn, evidence: evidence),
            Checks.dnssec((await dnssec).outcome, resolverName: reference.name),
            Checks.certificates(await certs),
            Checks.routerIdentity(router: context.router, mac: context.routerMAC, otherIPs: context.otherIPsWithRouterMAC, previousMAC: previousRouterMAC),
            Checks.networkDNS(servers: context.dnsFromNetwork, router: context.router, setOnMac: context.dnsSetOnMac,
                              devices: devices, trusted: trusted, offNetwork: await offNetwork),
            Checks.systemProxy(proxyReading(context)),
            Checks.pageIntegrity(.init(appleBody: appleResult?.body, firefoxBody: (await firefox)?.body, httpsUpgradeKept: upgradeKept)),
            Checks.wifiSecurity(isWiFi: context.isWiFi, securityRaw: context.securityRaw, securityName: context.security),
            Checks.networkMemory(NetworkMemory.assess(context, records: memory)),
            Checks.routingHealth(routing, vpnInterfaces: context.vpnInterfaces),
        ]
        let decided = VerdictRules.decide(findings, network: context, connected: true)
        return Report(date: Date(), network: context, findings: decided.findings, verdict: decided.verdict, reason: decided.reason,
                      provider: ownProvider, rewrites: publicRewrites, owners: owners,
                      filterCandidate: trusted ? candidate : nil)
    }

    /// P2: a DNS server set by hand on a private address outside this network — does it answer
    /// at all (over any route, a VPN's included)? nil when it doesn't apply.
    func offNetworkReading(_ context: NetworkContext) async -> Checks.OffNetworkDNS? {
        guard let first = context.dnsSetOnMac.first, Checks.isPrivate(first) else { return nil }
        let local = context.interfaceName.flatMap { NetworkReader.interfaces().ipv4[$0] }
        guard !Checks.sameSubnet(first, local?.address, local?.mask) else { return nil }
        let answered = await NetIO.dns(server: first, name: "a.root-servers.net", via: nil, timeout: 2).answered
        return Checks.OffNetworkDNS(address: first, answered: answered)
    }

    /// Tests the DNS server the Mac really uses; if it can't be reached over this network (e.g. a
    /// VPN-only server), tests the one the network handed out instead.
    func dnsAnswerReadings(_ context: NetworkContext, via: NWInterface.InterfaceType) async -> (readings: [Checks.AnchorReading], server: String?, fallback: Bool) {
        let candidates = (context.dnsServers.prefix(1) + context.dnsFromNetwork.prefix(1)).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
        var last: (readings: [Checks.AnchorReading], server: String?, fallback: Bool) = ([], nil, false)
        for (index, server) in candidates.enumerated() {
            let readings = await anchorReadings(server: server, via: via)
            last = (readings, server, index > 0)
            let answered = readings.contains { if case .addresses = $0.network { return true }; return $0.network == .blocked }
            if answered { return last }
        }
        return candidates.isEmpty ? (await anchorReadings(server: nil, via: via), nil, false) : last
    }

    func anchorReadings(server: String?, via: NWInterface.InterfaceType) async -> [Checks.AnchorReading] {
        await withTaskGroup(of: Checks.AnchorReading.self) { group in
            for anchor in Checks.anchors {
                group.addTask {
                    async let network: DNSOutcome = server == nil ? .error("no DNS server") : NetIO.dns(server: server!, name: anchor.name, via: via).outcome
                    var reference: DNSOutcome = .noAnswer
                    for candidate in self.reference.fallbackOrder {
                        reference = await NetIO.doh(name: anchor.name, endpoint: candidate.doh, certificateName: candidate.dohCertificateName)
                        if case .error = reference { continue }
                        break
                    }
                    return Checks.AnchorReading(name: anchor.name, expected: anchor.expected, network: await network, reference: reference)
                }
            }
            var all: [Checks.AnchorReading] = []
            for await reading in group { all.append(reading) }
            return all.sorted { $0.name < $1.name }
        }
    }

    func certReadings(via: NWInterface.InterfaceType) async -> [Checks.CertReading] {
        await withTaskGroup(of: Checks.CertReading.self) { group in
            for host in Checks.tlsHosts { group.addTask { await NetIO.tlsProbe(host: host, via: via) } }
            var all: [Checks.CertReading] = []
            for await reading in group { all.append(reading) }
            return all.sorted { $0.host < $1.host }
        }
    }

    /// Proxies configured on this Mac (as apps see them), plus this network's own address range.
    func proxyReading(_ context: NetworkContext) -> Checks.ProxyReading {
        let local = context.interfaceName.flatMap { NetworkReader.interfaces().ipv4[$0] }
        let p = NetworkReader.systemProxies()
        let workVPN = Automation.workVPNUp(vpnInterfaces: context.vpnInterfaces, ipv4: NetworkReader.interfaces().ipv4)
        return Checks.ProxyReading(entries: p.entries, autoConfigURL: p.autoConfigURL, autoDiscovery: p.autoDiscovery,
                                   localAddress: local?.address, localMask: local?.mask, vpnOn: workVPN)
    }

    func routingReading(_ context: NetworkContext) -> Checks.RoutingReading {
        let interfaces = NetworkReader.interfaces()
        let local = context.interfaceName.flatMap { interfaces.ipv4[$0] }
        return Checks.RoutingReading(
            routes: NetworkReader.routes(), router: context.router, physicalInterface: context.interfaceName,
            localAddress: local?.address, localMask: local?.mask,
            reachableGateways: NetworkReader.routerIdentity(router: nil).reachable, existingInterfaces: interfaces.names)
    }
}
