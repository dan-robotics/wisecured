import Foundation

// The ten checks as pure functions: readings in, one Finding out. No network I/O here, so every
// outcome can be tested with simulated readings (Tests/WiSecuredCoreTests).

public enum Checks {
    // MARK: Fixed test targets (all listed in the README)

    /// Names whose correct addresses are fixed and well known. The root servers are rarely
    /// blocked; DNS filters (e.g. Pi-hole lists) often block the DNS-provider names.
    public static let anchors: [(name: String, expected: Set<String>)] = [
        ("a.root-servers.net", ["198.41.0.4"]),
        ("k.root-servers.net", ["193.0.14.129"]),
        ("one.one.one.one", ["1.1.1.1", "1.0.0.1"]),
        ("dns.google", ["8.8.8.8", "8.8.4.4"]),
        ("dns.quad9.net", ["9.9.9.9", "149.112.112.112"]),
    ]
    /// A reserved documentation address (TEST-NET-1) where no DNS server exists.
    public static let testNetDNS = "192.0.2.53"
    /// Deliberately broken DNSSEC: a validating resolver must refuse it.
    public static let dnssecBrokenName = "dnssec-failed.org"
    public static let tlsHosts = ["www.apple.com", "www.google.com", "www.cloudflare.com", "www.wikipedia.org", "github.com"]
    public static let appleCaptiveBody = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
    public static let firefoxCaptiveBody = "success\n"

    // MARK: 1 · Captive portal

    public struct CaptiveReading: Sendable {
        public var body: String?
        public var error: String?
        public init(body: String?, error: String? = nil) { self.body = body; self.error = error }
    }

    public static func captivePortal(_ r: CaptiveReading) -> Finding {
        guard let body = r.body else {
            return Finding(.captivePortal, .unknown, summary: "Couldn't test",
                           seen: "Apple's test page did not load (\(r.error ?? "no answer")).",
                           meaning: "No internet yet, or the network blocks the test page.",
                           action: "If you expect a login page, open any website in a browser.")
        }
        if body.contains("Success") {
            return Finding(.captivePortal, .ok, summary: "None",
                           seen: "Apple's test page loaded normally.",
                           meaning: "No login page between you and the internet.")
        }
        return Finding(.captivePortal, .info, summary: "Login page",
                       seen: "Apple's test page was replaced by another page.",
                       meaning: "The network wants you to log in or accept terms first (normal in hotels and cafés). Until you do, it redirects traffic, so some checks can't run yet.",
                       action: "Open a browser, finish the login page, then click Check now.")
    }

    // MARK: 2 · DNS interception

    public static func dnsInterception(testNetAnswered: Bool?) -> Finding {
        guard let answered = testNetAnswered else {
            return Finding(.dnsInterception, .unknown, summary: "Couldn't test",
                           seen: "The test question could not be sent.", meaning: "No usable network connection.")
        }
        if answered {
            return Finding(.dnsInterception, .warn, summary: "Intercepted",
                           seen: "A DNS question sent to an address where no DNS server exists (\(testNetDNS)) got an answer.",
                           meaning: "Something on this network answers DNS questions meant for other servers. Hotels and captive portals often do this; it also lets the network change answers. The \"DNS answers\" check shows whether it did.",
                           action: "Prefer your hotspot or a VPN for anything private.")
        }
        return Finding(.dnsInterception, .ok, summary: "Not intercepted",
                       seen: "A DNS question to an address with no DNS server got no answer, as it should.",
                       meaning: "The network passes DNS questions through without answering them itself.")
    }

    // MARK: 3 · DNS answers

    public struct AnchorReading: Sendable {
        public var name: String
        public var expected: Set<String>
        /// Through the network's own DNS server.
        public var network: DNSOutcome
        /// Through encrypted DNS (DoH), which the network cannot change.
        public var reference: DNSOutcome
        public init(name: String, expected: Set<String>, network: DNSOutcome, reference: DNSOutcome) {
            self.name = name; self.expected = expected; self.network = network; self.reference = reference
        }
    }

    /// `server` = the DNS server that was asked (named in the finding).
    /// `fallback` = the Mac's own DNS server couldn't be reached over this network (typically a
    /// VPN's), so the network's DNS server was tested instead — the wording then says so.
    public static func dnsAnswers(_ readings: [AnchorReading], referenceName: String = "Quad9", server: String? = nil,
                                  fallback: Bool = false, vpnOn: Bool = false) -> Finding {
        let asked = server.map { " (\($0))" } ?? ""
        let who = fallback
            ? "The network's DNS\(asked) was tested — your \(vpnOn ? "VPN's DNS server" : "own DNS server") isn't reachable over this \(vpnOn ? "Wi-Fi" : "network"). It"
            : "Your DNS\(asked)"
        var mismatched: [String] = [], blocked: [String] = [], matched = 0, untested = 0
        for r in readings {
            // The truth is the encrypted answer when it worked, else the well-known addresses.
            let truth: Set<String> = { if case .addresses(let set) = r.reference { return set } else { return r.expected } }()
            switch r.network {
            case .addresses(let got):
                if got.isDisjoint(with: truth) && got.isDisjoint(with: r.expected) {
                    mismatched.append("\(r.name) → \(got.sorted().joined(separator: ", "))")
                } else { matched += 1 }
            case .blocked: blocked.append(r.name)
            default: untested += 1
            }
        }
        if !mismatched.isEmpty {
            return Finding(.dnsAnswers, .danger, summary: "Fake answers (\(mismatched.count) of \(readings.count))",
                           seen: "\(who) gave different addresses than encrypted \(referenceName): " + mismatched.joined(separator: "; ") + ".",
                           meaning: "The network is changing DNS answers. That can send you to fake copies of real websites.",
                           action: "Don't log in to anything here. Switch to your hotspot or use a VPN.")
        }
        if !blocked.isEmpty {
            return Finding(.dnsAnswers, .info, summary: matched > 0 ? "Filtered · others match" : "Filtered",
                           seen: "\(who) blocked \(blocked.joined(separator: ", ")) (answered 0.0.0.0 or \"not found\"). Encrypted \(referenceName) answered them normally.",
                           meaning: "A DNS filter is active, such as an ad-blocker (e.g. Pi-hole) or a parental/company filter. It blocks names but doesn't send you elsewhere.",
                           action: "Fine on your own network. On public Wi-Fi it means the network controls your DNS.")
        }
        if matched == 0 {
            return Finding(.dnsAnswers, .unknown, summary: "Couldn't test",
                           seen: "No usable DNS answers came back from\(asked.isEmpty ? " the DNS server" : asked) (\(untested) of \(readings.count) unanswered).",
                           meaning: "That DNS server didn't answer over this network, or there's no internet yet.")
        }
        return Finding(.dnsAnswers, .ok, summary: "Match \(referenceName)",
                       seen: "\(who) resolved \(matched) test name\(matched == 1 ? "" : "s") to the same addresses as encrypted \(referenceName).",
                       meaning: "The network isn't changing DNS answers.")
    }

    // MARK: 4 · DNSSEC

    public static func dnssec(_ outcome: DNSOutcome, resolverName: String = "Quad9") -> Finding {
        switch outcome {
        case .failed(rcode: 2):
            return Finding(.dnssec, .ok, summary: "Validates",
                           seen: "\(dnssecBrokenName) was refused by \(resolverName), as it must be.",
                           meaning: "DNS questions reach \(resolverName) unchanged and its security checks work.")
        case .addresses, .blocked:
            return Finding(.dnssec, .warn, summary: "Not validated",
                           seen: "\(dnssecBrokenName) (deliberately broken) was answered — \(resolverName) would have refused it.",
                           meaning: "Something on the network answered in \(resolverName)'s place, without DNS security checks. Usually the network's own DNS proxy.",
                           action: "Treat this network's DNS as untrusted.")
        default:
            return Finding(.dnssec, .info, summary: "Couldn't test",
                           seen: "\(resolverName) did not answer over plain DNS (\(outcome.label)).",
                           meaning: "Some networks block outside DNS servers. Not a sign of tampering on its own.")
        }
    }

    // MARK: 5 · Certificates

    public struct CertReading: Sendable {
        public var host: String
        public var connected: Bool
        public var trusted: Bool
        /// Chain ends at one of Apple's built-in root certificates (not one added on this Mac).
        public var builtInRoot: Bool
        public var issuer: String
        public var error: String?
        public init(host: String, connected: Bool, trusted: Bool, builtInRoot: Bool, issuer: String, error: String? = nil) {
            self.host = host; self.connected = connected; self.trusted = trusted
            self.builtInRoot = builtInRoot; self.issuer = issuer; self.error = error
        }
    }

    public static func certificates(_ readings: [CertReading]) -> Finding {
        let reached = readings.filter(\.connected)
        guard !reached.isEmpty else {
            return Finding(.certificates, .unknown, summary: "Couldn't test",
                           seen: "None of the \(readings.count) test sites could be reached.",
                           meaning: "No internet yet, or a login page is in the way.")
        }
        let bad = reached.filter { !$0.trusted }
        if !bad.isEmpty {
            return Finding(.certificates, .danger, summary: "Invalid certificate",
                           seen: bad.map { "\($0.host): not trusted (issuer \($0.issuer))" }.joined(separator: "; ") + ".",
                           meaning: "Someone presented a fake certificate for a well-known site — typical of a man-in-the-middle trying to read encrypted traffic.",
                           action: "Don't log in to anything here. Switch to your hotspot.")
        }
        let custom = reached.filter { !$0.builtInRoot }
        if !custom.isEmpty {
            let issuers = Set(custom.map(\.issuer)).sorted().joined(separator: ", ")
            return Finding(.certificates, .warn, summary: "Unexpected issuer",
                           seen: "\(custom.count) of \(reached.count) sites were signed by \(issuers), a certificate authority added to this Mac rather than a built-in one.",
                           meaning: "Most likely a company proxy or security software that inspects HTTPS. Whoever controls it can read your encrypted traffic.",
                           action: "Expected on a work-managed Mac. If you didn't install anything like that, don't use this network for anything private.")
        }
        return Finding(.certificates, .ok, summary: "Normal · \(reached.count) site\(reached.count == 1 ? "" : "s")",
                       seen: "All \(reached.count) test sites presented valid certificates from built-in authorities.",
                       meaning: "Nobody is intercepting HTTPS on this network.")
    }

    // MARK: 6 · Router identity

    public static func routerIdentity(router: String?, mac: String?, otherIPs: [String], previousMAC: String?) -> Finding {
        guard let router, let mac else {
            return Finding(.routerIdentity, .unknown, summary: "Couldn't read",
                           seen: "The router's hardware address isn't in this Mac's address table\(router == nil ? " (no router)" : "").",
                           meaning: "Normal right after joining a network; WiSecured tries again every few seconds.")
        }
        if let previousMAC, previousMAC != mac {
            return Finding(.routerIdentity, .danger, summary: "Router changed",
                           seen: "The router \(router) had hardware address \(previousMAC); now \(mac) answers for it.",
                           meaning: "Another device is answering as the router — the classic way to put yourself in the middle of everyone's traffic. (Rarely: the router was just replaced or restarted as a different unit.)",
                           action: "Switch to your hotspot until you know why.")
        }
        if !otherIPs.isEmpty {
            return Finding(.routerIdentity, .warn, summary: "Address shared",
                           seen: "The router's hardware address \(mac) is also used by \(otherIPs.joined(separator: ", ")).",
                           meaning: "Either the router simply has several addresses, or a device is impersonating it.",
                           action: "If this appears suddenly on public Wi-Fi, switch to your hotspot.")
        }
        return Finding(.routerIdentity, .ok, summary: previousMAC == nil ? "Recorded" : "Unchanged",
                       seen: "Router \(router) answers with hardware address \(mac)\(previousMAC == nil ? "" : ", same as before").",
                       meaning: "Nothing is pretending to be the router. Watched every few seconds.")
    }

    // MARK: 7 · Network DNS server

    /// `servers` = handed out by the network (rogue-DHCP check); `setOnMac` = set by hand on this
    /// Mac (overrides the network's; DNS-changer malware does the same, so it is always shown).
    public static func networkDNS(servers: [String], router: String?, setOnMac: [String] = []) -> Finding {
        if !setOnMac.isEmpty {
            let handed = servers.isEmpty ? "nothing" : servers.joined(separator: ", ") + (servers.first == router ? " (the router)" : "")
            return Finding(.networkDNS, .info, summary: "Set on this Mac",
                           seen: "This Mac uses \(setOnMac.joined(separator: ", ")), set by hand (System Settings or a script). The network hands out \(handed).",
                           meaning: "Your own DNS choice overrides the network's — normal if you set it (e.g. Pi-hole, Quad9). If you didn't, DNS-changer malware does exactly this.",
                           action: "If you don't recognise \(setOnMac.first!), check System Settings › Network › Wi-Fi › Details › DNS.")
        }
        guard !servers.isEmpty else {
            return Finding(.networkDNS, .unknown, summary: "None", seen: "No DNS server is configured.", meaning: "No network, or still connecting.")
        }
        let tailscale = servers.filter { $0 == "100.100.100.100" }
        let others = servers.filter { $0 != router && !tailscale.contains($0) }
        let privateOthers = others.filter(isPrivate)
        if !privateOthers.isEmpty {
            return Finding(.networkDNS, .info, summary: "Another local device",
                           seen: "DNS questions go to \(privateOthers.joined(separator: ", ")) — a device on this network that isn't the router (\(router ?? "?")).",
                           meaning: "Normal at home if it's your own DNS filter (e.g. Pi-hole). On public Wi-Fi it means another device decides where names lead.",
                           action: "On public Wi-Fi, prefer your hotspot or a VPN.")
        }
        let summary = others.isEmpty ? (tailscale.isEmpty ? "The router" : "Tailscale") : "Public DNS"
        return Finding(.networkDNS, .ok, summary: summary,
                       seen: "DNS servers: \(servers.joined(separator: ", ")).",
                       meaning: tailscale.isEmpty ? "DNS is handled by the router or a public service." : "Tailscale's MagicDNS handles DNS (encrypted inside your tailnet).")
    }

    static func isPrivate(_ ip: String) -> Bool {
        let p = ip.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4 else { return ip.lowercased().hasPrefix("fd") || ip.lowercased().hasPrefix("fe80") }
        return p[0] == 10 || (p[0] == 172 && (16...31).contains(p[1])) || (p[0] == 192 && p[1] == 168)
    }

    // MARK: 8 · Page integrity

    public struct PageReading: Sendable {
        /// Body of Apple's plain-HTTP test page (nil = didn't load).
        public var appleBody: String?
        /// Body of Firefox's plain-HTTP test page (nil = didn't load).
        public var firefoxBody: String?
        /// For http://www.apple.com: true = redirected to https, false = served over plain http, nil = no answer.
        public var httpsUpgradeKept: Bool?
        public init(appleBody: String?, firefoxBody: String?, httpsUpgradeKept: Bool?) {
            self.appleBody = appleBody; self.firefoxBody = firefoxBody; self.httpsUpgradeKept = httpsUpgradeKept
        }
    }

    public static func pageIntegrity(_ r: PageReading) -> Finding {
        var changed: [String] = []
        if let body = r.appleBody, body.contains("Success"), body.trimmingCharacters(in: .whitespacesAndNewlines) != appleCaptiveBody {
            changed.append("Apple's test page had extra content")
        }
        if let body = r.firefoxBody, body.contains("success"), body != firefoxCaptiveBody {
            changed.append("Firefox's test page had extra content")
        }
        if r.httpsUpgradeKept == false { changed.append("http://www.apple.com was NOT redirected to https") }
        if !changed.isEmpty {
            return Finding(.pageIntegrity, .danger, summary: "Modified",
                           seen: changed.joined(separator: "; ") + ".",
                           meaning: "The network is changing web traffic in transit (injecting content or stripping the switch to HTTPS).",
                           action: "Don't log in to anything here. Switch to your hotspot.")
        }
        if r.appleBody == nil && r.firefoxBody == nil && r.httpsUpgradeKept == nil {
            return Finding(.pageIntegrity, .unknown, summary: "Couldn't test",
                           seen: "The test pages didn't load.", meaning: "No internet yet, or a login page is in the way.")
        }
        return Finding(.pageIntegrity, .ok, summary: "Unchanged",
                       seen: "Test pages arrived exactly as published and the switch to HTTPS was kept.",
                       meaning: "Nothing is modifying web traffic on this network.")
    }

    // MARK: 9 · Wi-Fi security

    public static func wifiSecurity(isWiFi: Bool, securityRaw: Int?, securityName: String) -> Finding {
        guard isWiFi else {
            return Finding(.wifiSecurity, .ok, summary: "Wired", seen: "Connected by cable, not Wi-Fi.", meaning: "Nobody can listen in over the air.")
        }
        guard let raw = securityRaw, raw >= 0, raw < 1000 else {
            return Finding(.wifiSecurity, .unknown, summary: "Unknown",
                           seen: "macOS didn't report the security type.", meaning: "Usually missing Location permission.",
                           action: "Allow Location for WiSecured in System Settings › Privacy & Security.")
        }
        switch raw {
        case 0:
            return Finding(.wifiSecurity, .warn, summary: "Open · no password",
                           seen: "This Wi-Fi has no password and no encryption.",
                           meaning: "Anyone nearby can read traffic that isn't encrypted (most websites are, but not everything).",
                           action: "Use your hotspot or a VPN for anything private.")
        case 1, 6:
            return Finding(.wifiSecurity, .warn, summary: "WEP (broken)",
                           seen: "This Wi-Fi uses WEP.", meaning: "WEP was broken years ago; treat it like an open network.",
                           action: "Use your hotspot or a VPN.")
        case 2, 3, 7, 8:
            return Finding(.wifiSecurity, .ok, summary: securityName,
                           seen: "This Wi-Fi uses \(securityName).",
                           meaning: "Encrypted. On public Wi-Fi everyone who knows the password is still on the same network as you.")
        case 14, 15:
            return Finding(.wifiSecurity, .info, summary: "Enhanced Open",
                           seen: "This Wi-Fi uses Enhanced Open (OWE).",
                           meaning: "Encrypted over the air, but anyone can join, so other users are still on the same network.")
        default:
            return Finding(.wifiSecurity, .ok, summary: securityName,
                           seen: "This Wi-Fi uses \(securityName).",
                           meaning: "Encrypted. On public Wi-Fi everyone who knows the password is still on the same network as you.")
        }
    }

    // MARK: 10 · Routing health

    public struct RouteEntry: Sendable, Equatable {
        public var destination: String
        public var gateway: String
        public var interface: String
        public var flags: UInt32
        public init(destination: String, gateway: String, interface: String, flags: UInt32) {
            self.destination = destination; self.gateway = gateway; self.interface = interface; self.flags = flags
        }
        static let ifScope: UInt32 = 0x1000000      // RTF_IFSCOPE: per-interface copy, not the main table
        static let staticFlag: UInt32 = 0x800       // RTF_STATIC: added by hand or a script (route add)
        static let wasCloned: UInt32 = 0x20000      // RTF_WASCLONED: temporary, made by macOS for active traffic
        public var isDefault: Bool { destination == "0.0.0.0" || destination == "default" }
        public var isScoped: Bool { flags & Self.ifScope != 0 }
        public var gatewayIsAddress: Bool { gateway.split(separator: ".").count == 4 }
        /// A route someone added on purpose (not macOS' temporary per-connection copies).
        public var isManual: Bool { flags & Self.staticFlag != 0 && flags & Self.wasCloned == 0 }
    }

    public struct RoutingReading: Sendable {
        public var routes: [RouteEntry]
        /// The network's real router on the Wi-Fi/Ethernet interface.
        public var router: String?
        public var physicalInterface: String?
        /// The Mac's own address and mask on that interface.
        public var localAddress: String?
        public var localMask: String?
        /// Gateways that answered recently (present in the address table).
        public var reachableGateways: Set<String>
        /// Interfaces that exist right now.
        public var existingInterfaces: Set<String>
        public init(routes: [RouteEntry], router: String?, physicalInterface: String?, localAddress: String?, localMask: String?,
                    reachableGateways: Set<String>, existingInterfaces: Set<String>) {
            self.routes = routes; self.router = router; self.physicalInterface = physicalInterface
            self.localAddress = localAddress; self.localMask = localMask
            self.reachableGateways = reachableGateways; self.existingInterfaces = existingInterfaces
        }
    }

    public static func routingHealth(_ r: RoutingReading, vpnInterfaces: [String]) -> Finding {
        // Dead routes: on the physical interface, via a gateway that is not the router and either
        // is outside this network's subnet or hasn't answered (e.g. leftovers from a VPN or
        // split tunnel set up on another network whose router address falls inside this subnet).
        var deadByGateway: [String: Int] = [:]
        for route in r.routes where route.isManual && route.interface == r.physicalInterface && route.gatewayIsAddress
            && !route.isDefault && route.gateway != r.router {
            let onSubnet = sameSubnet(route.gateway, r.localAddress, r.localMask)
            if !onSubnet || !r.reachableGateways.contains(route.gateway) {
                deadByGateway[route.gateway, default: 0] += 1
            }
        }
        let leftovers = Set(r.routes.filter { !$0.interface.isEmpty && !r.existingInterfaces.contains($0.interface) }.map(\.interface))
        let defaults = r.routes.filter { $0.isDefault && !$0.isScoped }
        let defaultInterfaces = Set(defaults.map(\.interface))
        let vpnText = vpnInterfaces.isEmpty ? "No VPN tunnel is up." : "VPN tunnels up: \(vpnInterfaces.joined(separator: ", "))."

        var problems: [String] = []
        if !deadByGateway.isEmpty {
            problems.append(deadByGateway.sorted { $0.key < $1.key }
                .map { "\($0.value) route\($0.value == 1 ? "" : "s") via \($0.key), which isn't reachable on this network" }
                .joined(separator: "; "))
        }
        if !leftovers.isEmpty { problems.append("routes left on interfaces that no longer exist: \(leftovers.sorted().joined(separator: ", "))") }
        if defaultInterfaces.count > 1 { problems.append("\(defaultInterfaces.count) default routes compete (\(defaultInterfaces.sorted().joined(separator: ", ")))") }

        if !problems.isEmpty {
            return Finding(.routingHealth, .warn, summary: deadByGateway.isEmpty ? "Conflicts" : "Dead routes",
                           seen: problems.joined(separator: "; ").prefix(1).uppercased() + problems.joined(separator: "; ").dropFirst() + ". " + vpnText,
                           meaning: "Traffic to some addresses goes nowhere — usually leftovers from a VPN or split-tunnel set up on another network. Not an attack, but apps can fail in odd ways.",
                           action: "Remove the leftover routes with the tool that created them (or reconnect the VPN).")
        }
        let via = defaults.first.map { " Default route: \($0.interface)\($0.gatewayIsAddress ? " via \($0.gateway)" : "")." } ?? ""
        // Extra routes pinned to the router (split-tunnel style, e.g. to keep some traffic off a VPN).
        let pinned = r.routes.filter { $0.isManual && $0.interface == r.physicalInterface && !$0.isDefault && $0.gateway == r.router }.count
        let pinnedText = pinned >= 5 ? " \(pinned) routes are pinned to the router (split-tunnel style); the router answers, so they work." : ""
        let summary = vpnInterfaces.isEmpty ? (pinned >= 5 ? "Clean · \(pinned) pinned" : "Clean") : "Clean · VPN on"
        return Finding(.routingHealth, vpnInterfaces.isEmpty ? .ok : .info, summary: summary,
                       seen: vpnText + via + pinnedText, meaning: "No dead or conflicting routes.")
    }

    static func sameSubnet(_ a: String, _ b: String?, _ mask: String?) -> Bool {
        guard let b, let mask, let x = ipv4(a), let y = ipv4(b), let m = ipv4(mask) else { return false }
        return x & m == y & m
    }

    static func ipv4(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4, parts.allSatisfy({ $0 < 256 }) else { return nil }
        return parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]
    }
}
