import Foundation
import Network

/// Runs the ten checks against the current network and returns one Report. Read-only: it reads
/// local state and sends test questions; it never changes a setting or a route.
public struct Checker: Sendable {
    public enum Reference: String, Sendable, CaseIterable {
        case quad9, cloudflare
        public var name: String { self == .quad9 ? "Quad9" : "Cloudflare" }
        var doh: URL { self == .quad9 ? NetIO.quad9DoH : NetIO.cloudflareDoH }
        var plainDNS: String { self == .quad9 ? "9.9.9.9" : "1.1.1.1" }
        var other: Reference { self == .quad9 ? .cloudflare : .quad9 }
    }

    public var reference: Reference

    public init(reference: Reference = .quad9) { self.reference = reference }

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

    public func run(physical: (name: String, isWiFi: Bool)?, isExpensive: Bool, previousRouterMAC: String?) async -> Report {
        let context = context(physical: physical, isExpensive: isExpensive)
        guard physical != nil else {
            let decided = VerdictRules.decide([], network: context, connected: false)
            return Report(date: Date(), network: context, findings: [], verdict: decided.verdict, reason: decided.reason)
        }
        let via: NWInterface.InterfaceType = context.isWiFi ? .wifi : .wiredEthernet

        async let apple = NetIO.httpGet(host: "captive.apple.com", path: "/hotspot-detect.html", via: via)
        async let firefox = NetIO.httpGet(host: "detectportal.firefox.com", path: "/success.txt", via: via)
        async let upgrade = NetIO.httpGet(host: "www.apple.com", path: "/", via: via)
        async let testNet = NetIO.dns(server: Checks.testNetDNS, name: "one.one.one.one", via: via, timeout: 2)
        async let dnssec = NetIO.dns(server: reference.plainDNS, name: Checks.dnssecBrokenName, via: via, timeout: 4)
        async let anchors = dnsAnswerReadings(context, via: via)
        async let certs = certReadings(via: via)

        let appleResult = await apple
        let upgradeResult = await upgrade
        let upgradeKept: Bool? = upgradeResult.map { r in
            (300...399).contains(r.status) && (r.headers["location"]?.lowercased().hasPrefix("https://") ?? false)
        }
        let routing = routingReading(context)

        let findings: [Finding] = [
            Checks.captivePortal(.init(body: appleResult?.body, error: appleResult == nil ? "no answer" : nil)),
            Checks.dnsInterception(testNetAnswered: (await testNet).answered),
            Checks.dnsAnswers((await anchors).readings, referenceName: reference.name, server: (await anchors).server,
                              fallback: (await anchors).fallback, vpnOn: context.vpnOn),
            Checks.dnssec((await dnssec).outcome, resolverName: reference.name),
            Checks.certificates(await certs),
            Checks.routerIdentity(router: context.router, mac: context.routerMAC, otherIPs: context.otherIPsWithRouterMAC, previousMAC: previousRouterMAC),
            Checks.networkDNS(servers: context.dnsFromNetwork, router: context.router, setOnMac: context.dnsSetOnMac),
            Checks.pageIntegrity(.init(appleBody: appleResult?.body, firefoxBody: (await firefox)?.body, httpsUpgradeKept: upgradeKept)),
            Checks.wifiSecurity(isWiFi: context.isWiFi, securityRaw: context.securityRaw, securityName: context.security),
            Checks.routingHealth(routing, vpnInterfaces: context.vpnInterfaces),
        ]
        let decided = VerdictRules.decide(findings, network: context, connected: true)
        return Report(date: Date(), network: context, findings: decided.findings, verdict: decided.verdict, reason: decided.reason)
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
                    var reference = await NetIO.doh(name: anchor.name, endpoint: self.reference.doh)
                    if case .error = reference { reference = await NetIO.doh(name: anchor.name, endpoint: self.reference.other.doh) }
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

    func routingReading(_ context: NetworkContext) -> Checks.RoutingReading {
        let interfaces = NetworkReader.interfaces()
        let local = context.interfaceName.flatMap { interfaces.ipv4[$0] }
        return Checks.RoutingReading(
            routes: NetworkReader.routes(), router: context.router, physicalInterface: context.interfaceName,
            localAddress: local?.address, localMask: local?.mask,
            reachableGateways: NetworkReader.routerIdentity(router: nil).reachable, existingInterfaces: interfaces.names)
    }
}
