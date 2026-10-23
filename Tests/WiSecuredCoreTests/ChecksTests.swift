import XCTest
@testable import WiSecuredCore

// Every check, every outcome, from simulated readings — no network, nothing real is touched.

final class DNSMessageTests: XCTestCase {
    func testQueryLayout() {
        let q = [UInt8](DNSMessage.query(name: "apple.com"))
        XCTAssertEqual(q.count, 12 + 1 + 5 + 1 + 3 + 1 + 4)
        XCTAssertEqual(Array(q[12...17]), [5, 97, 112, 112, 108, 101])   // "\5apple"
        XCTAssertEqual(Array(q.suffix(4)), [0, 1, 0, 1])                  // type A, class IN
    }

    /// A real-shaped answer: header + question + two compressed A records.
    func testParseTwoARecords() {
        var d = [UInt8](DNSMessage.query(name: "one.one.one.one"))
        d[2] = 0x81; d[3] = 0x80; d[7] = 2                                // response, OK, 2 answers
        for ip in [[1, 1, 1, 1], [1, 0, 0, 1]] as [[UInt8]] {
            d += [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4] + ip
        }
        let r = DNSMessage.parse(Data(d))
        XCTAssertEqual(r?.rcode, 0)
        XCTAssertEqual(r?.addresses, ["1.1.1.1", "1.0.0.1"])
        XCTAssertEqual(DNSOutcome(r), .addresses(["1.1.1.1", "1.0.0.1"]))
    }

    func testOutcomes() {
        XCTAssertEqual(DNSOutcome(DNSMessage.Response(rcode: 3, addresses: [])), .blocked)
        XCTAssertEqual(DNSOutcome(DNSMessage.Response(rcode: 0, addresses: ["0.0.0.0"])), .blocked)
        XCTAssertEqual(DNSOutcome(DNSMessage.Response(rcode: 2, addresses: [])), .failed(rcode: 2))
        XCTAssertEqual(DNSOutcome(nil), .noAnswer)
        XCTAssertNil(DNSMessage.parse(Data([1, 2, 3])))
    }
}

final class ChecksTests: XCTestCase {
    func testCaptivePortal() {
        XCTAssertEqual(Checks.captivePortal(.init(body: Checks.appleCaptiveBody)).status, .ok)
        XCTAssertEqual(Checks.captivePortal(.init(body: "<html>Hotel login</html>")).status, .info)
        XCTAssertEqual(Checks.captivePortal(.init(body: nil, error: "timeout")).status, .unknown)
    }

    func testDNSInterception() {
        XCTAssertEqual(Checks.dnsInterception(testNetAnswered: false).status, .ok)
        XCTAssertEqual(Checks.dnsInterception(testNetAnswered: true).status, .warn)
        XCTAssertEqual(Checks.dnsInterception(testNetAnswered: nil).status, .unknown)
    }

    private func anchor(_ network: DNSOutcome, reference: DNSOutcome = .addresses(["1.1.1.1", "1.0.0.1"])) -> Checks.AnchorReading {
        .init(name: "one.one.one.one", expected: ["1.1.1.1", "1.0.0.1"], network: network, reference: reference)
    }

    func testDNSAnswers() {
        XCTAssertEqual(Checks.dnsAnswers([anchor(.addresses(["1.1.1.1", "1.0.0.1"]))]).status, .ok)
        XCTAssertEqual(Checks.dnsAnswers([anchor(.addresses(["1.1.1.1"]))]).status, .ok, "a subset is still a match")
        XCTAssertEqual(Checks.dnsAnswers([anchor(.addresses(["203.0.113.66"]))]).status, .danger, "fake answer")
        XCTAssertEqual(Checks.dnsAnswers([anchor(.blocked)]).status, .info, "Pi-hole-style filter is not an attack")
        XCTAssertEqual(Checks.dnsAnswers([anchor(.noAnswer)]).status, .unknown)
        // Reference failed: fall back to the well-known addresses.
        XCTAssertEqual(Checks.dnsAnswers([anchor(.addresses(["1.0.0.1"]), reference: .error("timeout"))]).status, .ok)
        XCTAssertEqual(Checks.dnsAnswers([anchor(.addresses(["10.0.0.9"]), reference: .error("timeout"))]).status, .danger)
    }

    func testDNSSEC() {
        XCTAssertEqual(Checks.dnssec(.failed(rcode: 2)).status, .ok)
        XCTAssertEqual(Checks.dnssec(.addresses(["1.2.3.4"])).status, .warn)
        XCTAssertEqual(Checks.dnssec(.noAnswer).status, .info)
    }

    func testCertificates() {
        let good = Checks.CertReading(host: "www.apple.com", connected: true, trusted: true, builtInRoot: true, issuer: "Apple Public EV Server RSA CA 1")
        let company = Checks.CertReading(host: "github.com", connected: true, trusted: true, builtInRoot: false, issuer: "Corp Firewall CA")
        let fake = Checks.CertReading(host: "www.google.com", connected: true, trusted: false, builtInRoot: false, issuer: "Evil CA")
        let down = Checks.CertReading(host: "x", connected: false, trusted: false, builtInRoot: false, issuer: "", error: "timeout")
        XCTAssertEqual(Checks.certificates([good, down]).status, .ok)
        XCTAssertEqual(Checks.certificates([good, company]).status, .warn, "company proxy = yellow, never red")
        XCTAssertEqual(Checks.certificates([good, company, fake]).status, .danger)
        XCTAssertEqual(Checks.certificates([down]).status, .unknown)
    }

    func testRouterIdentity() {
        XCTAssertEqual(Checks.routerIdentity(router: "192.168.1.1", mac: "aa:bb:cc:dd:ee:ff", otherIPs: [], previousMAC: nil).status, .ok)
        XCTAssertEqual(Checks.routerIdentity(router: "192.168.1.1", mac: "aa:bb:cc:dd:ee:ff", otherIPs: [], previousMAC: "aa:bb:cc:dd:ee:ff").summary, "Unchanged")
        XCTAssertEqual(Checks.routerIdentity(router: "192.168.1.1", mac: "11:22:33:44:55:66", otherIPs: [], previousMAC: "aa:bb:cc:dd:ee:ff").status, .danger)
        XCTAssertEqual(Checks.routerIdentity(router: "192.168.1.1", mac: "aa:bb:cc:dd:ee:ff", otherIPs: ["192.168.1.50"], previousMAC: nil).status, .warn)
        XCTAssertEqual(Checks.routerIdentity(router: "192.168.1.1", mac: nil, otherIPs: [], previousMAC: nil).status, .unknown)
    }

    func testNetworkDNS() {
        XCTAssertEqual(Checks.networkDNS(servers: ["192.168.1.1"], router: "192.168.1.1").status, .ok)
        XCTAssertEqual(Checks.networkDNS(servers: ["192.168.1.53"], router: "192.168.1.1").status, .info, "Pi-hole-style local DNS")
        XCTAssertEqual(Checks.networkDNS(servers: ["9.9.9.9"], router: "192.168.1.1").summary, "Public DNS")
        XCTAssertEqual(Checks.networkDNS(servers: ["100.100.100.100"], router: "192.168.1.1").summary, "Tailscale")
        XCTAssertEqual(Checks.networkDNS(servers: [], router: nil).status, .unknown)
        // Common home setup: the router is handed out by DHCP, a local DNS filter is set by hand on the Mac.
        let manual = Checks.networkDNS(servers: ["192.168.1.1"], router: "192.168.1.1", setOnMac: ["192.168.1.53"])
        XCTAssertEqual(manual.status, .info)
        XCTAssertEqual(manual.summary, "Set on this Mac")
        XCTAssertTrue(manual.seen.contains("192.168.1.53") && manual.seen.contains("192.168.1.1 (the router)"), manual.seen)
    }

    /// A local DNS filter: root servers match, DNS-provider names blocked.
    func testDNSAnswersFilteredButHonest() {
        let readings: [Checks.AnchorReading] = [
            .init(name: "a.root-servers.net", expected: ["198.41.0.4"], network: .addresses(["198.41.0.4"]), reference: .addresses(["198.41.0.4"])),
            .init(name: "dns.google", expected: ["8.8.8.8", "8.8.4.4"], network: .blocked, reference: .addresses(["8.8.8.8", "8.8.4.4"])),
        ]
        let f = Checks.dnsAnswers(readings, server: "192.168.1.53")
        XCTAssertEqual(f.status, .info)
        XCTAssertEqual(f.summary, "Filtered · others match")
    }

    /// With a VPN on, the VPN's DNS can't be reached over Wi-Fi, so the
    /// router's DNS is tested — the wording must say so (result and colour unchanged).
    func testDNSAnswersFallbackWording() {
        let readings: [Checks.AnchorReading] = [.init(name: "dns.google", expected: ["8.8.8.8"], network: .blocked, reference: .addresses(["8.8.8.8"]))]
        let normal = Checks.dnsAnswers(readings, server: "192.168.1.53")
        let viaVPN = Checks.dnsAnswers(readings, server: "192.168.1.1", fallback: true, vpnOn: true)
        XCTAssertTrue(normal.seen.hasPrefix("Your DNS (192.168.1.53) blocked"), normal.seen)
        XCTAssertTrue(viaVPN.seen.hasPrefix("The network's DNS (192.168.1.1) was tested — your VPN's DNS server isn't reachable over this Wi-Fi. It blocked"), viaVPN.seen)
        XCTAssertEqual(normal.status, viaVPN.status)
        XCTAssertEqual(normal.summary, viaVPN.summary)
    }

    func testDoHReachedByIP() {
        XCTAssertEqual(NetIO.quad9DoH.host, "9.9.9.9")
        XCTAssertEqual(NetIO.cloudflareDoH.host, "1.1.1.1")
    }

    func testDNSAnswersNamesTheServer() {
        let f = Checks.dnsAnswers([.init(name: "dns.google", expected: ["8.8.8.8"], network: .blocked, reference: .addresses(["8.8.8.8"]))], server: "192.168.1.53")
        XCTAssertTrue(f.seen.contains("192.168.1.53"), f.seen)
    }

    func testRoutingHealthPinnedRoutes() {
        let pinned = (1...120).map { Checks.RouteEntry(destination: "17.0.\($0).0", gateway: "192.168.1.1", interface: "en0", flags: 0x800) }
            + (1...80).map { Checks.RouteEntry(destination: "17.1.\($0).1", gateway: "192.168.1.1", interface: "en0", flags: 0x20000) }   // temporary copies
        let reading = Checks.RoutingReading(routes: [Checks.RouteEntry(destination: "0.0.0.0", gateway: "192.168.1.1", interface: "en0", flags: 0)] + pinned,
                                            router: "192.168.1.1", physicalInterface: "en0", localAddress: "192.168.1.20", localMask: "255.255.255.0",
                                            reachableGateways: ["192.168.1.1"], existingInterfaces: ["en0"])
        let f = Checks.routingHealth(reading, vpnInterfaces: [])
        XCTAssertEqual(f.status, .ok)
        XCTAssertEqual(f.summary, "Clean · 120 pinned")
    }

    func testPageIntegrity() {
        XCTAssertEqual(Checks.pageIntegrity(.init(appleBody: Checks.appleCaptiveBody, firefoxBody: "success\n", httpsUpgradeKept: true)).status, .ok)
        XCTAssertEqual(Checks.pageIntegrity(.init(appleBody: Checks.appleCaptiveBody + "<script>ad()</script>", firefoxBody: "success\n", httpsUpgradeKept: true)).status, .danger, "injected content")
        XCTAssertEqual(Checks.pageIntegrity(.init(appleBody: Checks.appleCaptiveBody, firefoxBody: "success\n", httpsUpgradeKept: false)).status, .danger, "HTTPS stripped")
        XCTAssertEqual(Checks.pageIntegrity(.init(appleBody: nil, firefoxBody: nil, httpsUpgradeKept: nil)).status, .unknown)
    }

    func testWiFiSecurity() {
        XCTAssertEqual(Checks.wifiSecurity(isWiFi: true, securityRaw: 0, securityName: "Open").status, .warn)
        XCTAssertEqual(Checks.wifiSecurity(isWiFi: true, securityRaw: 1, securityName: "WEP").status, .warn)
        XCTAssertEqual(Checks.wifiSecurity(isWiFi: true, securityRaw: 4, securityName: "WPA2 Personal").status, .ok)
        XCTAssertEqual(Checks.wifiSecurity(isWiFi: true, securityRaw: 11, securityName: "WPA3 Personal").status, .ok)
        XCTAssertEqual(Checks.wifiSecurity(isWiFi: true, securityRaw: 14, securityName: "OWE").status, .info)
        XCTAssertEqual(Checks.wifiSecurity(isWiFi: false, securityRaw: nil, securityName: "").summary, "Wired")
        XCTAssertEqual(Checks.wifiSecurity(isWiFi: true, securityRaw: nil, securityName: "unknown").status, .unknown)
    }

    /// Leftover routes from another network: routes via 192.168.1.1 on a 192.168.0.0/20 network that contains that address but has no such router.
    func testRoutingHealthDeadRoutes() {
        let routes = [
            Checks.RouteEntry(destination: "0.0.0.0", gateway: "192.168.0.1", interface: "en0", flags: 0),
            Checks.RouteEntry(destination: "17.0.0.0", gateway: "192.168.1.1", interface: "en0", flags: 0x800),
            Checks.RouteEntry(destination: "157.240.0.0", gateway: "192.168.1.1", interface: "en0", flags: 0x800),
            // macOS' temporary per-connection copy via the dead gateway: not counted.
            Checks.RouteEntry(destination: "17.253.144.10", gateway: "192.168.1.1", interface: "en0", flags: 0x800 | 0x20000),
        ]
        let reading = Checks.RoutingReading(routes: routes, router: "192.168.0.1", physicalInterface: "en0",
                                            localAddress: "192.168.3.20", localMask: "255.255.240.0",
                                            reachableGateways: ["192.168.0.1"], existingInterfaces: ["en0"])
        let f = Checks.routingHealth(reading, vpnInterfaces: [])
        XCTAssertEqual(f.status, .warn)
        XCTAssertTrue(f.seen.contains("2 routes via 192.168.1.1"), f.seen)
    }

    func testRoutingHealthCleanAndConflicts() {
        let clean = Checks.RoutingReading(routes: [Checks.RouteEntry(destination: "0.0.0.0", gateway: "192.168.1.1", interface: "en0", flags: 0)],
                                          router: "192.168.1.1", physicalInterface: "en0", localAddress: "192.168.1.20",
                                          localMask: "255.255.255.0", reachableGateways: ["192.168.1.1"], existingInterfaces: ["en0", "utun4"])
        XCTAssertEqual(Checks.routingHealth(clean, vpnInterfaces: []).status, .ok)
        XCTAssertEqual(Checks.routingHealth(clean, vpnInterfaces: ["utun4"]).status, .info)

        var twoDefaults = clean
        twoDefaults.routes.append(Checks.RouteEntry(destination: "0.0.0.0", gateway: "link#20", interface: "utun4", flags: 0))
        XCTAssertEqual(Checks.routingHealth(twoDefaults, vpnInterfaces: ["utun4"]).summary, "Conflicts")

        var scoped = clean
        scoped.routes.append(Checks.RouteEntry(destination: "0.0.0.0", gateway: "link#20", interface: "utun4", flags: 0x1000000))
        XCTAssertEqual(Checks.routingHealth(scoped, vpnInterfaces: ["utun4"]).status, .info, "scoped defaults are not conflicts")

        var leftover = clean
        leftover.routes.append(Checks.RouteEntry(destination: "10.0.0.0", gateway: "link#30", interface: "utun9", flags: 0))
        XCTAssertEqual(Checks.routingHealth(leftover, vpnInterfaces: []).status, .warn)
    }
}

final class VerdictTests: XCTestCase {
    private let net = NetworkContext(isWiFi: true, ssid: "Cafe")

    private func f(_ id: CheckID, _ s: CheckStatus) -> Finding { Finding(id, s, summary: "x", seen: "", meaning: "", action: "Act.") }

    func testSafe() {
        XCTAssertEqual(VerdictRules.decide(CheckID.allCases.map { f($0, .ok) }, network: net, connected: true).verdict, .safe)
    }

    func testDangerWins() {
        var all = CheckID.allCases.map { f($0, .ok) }
        all[2] = f(.dnsAnswers, .danger)
        all[8] = f(.wifiSecurity, .warn)
        XCTAssertEqual(VerdictRules.decide(all, network: net, connected: true).verdict, .danger)
    }

    func testWarnIsCareful() {
        var all = CheckID.allCases.map { f($0, .ok) }
        all[8] = f(.wifiSecurity, .warn)
        XCTAssertEqual(VerdictRules.decide(all, network: net, connected: true).verdict, .careful)
    }

    /// A hotel login page must never produce a false red.
    func testLoginPageSuppressesRed() {
        var all = CheckID.allCases.map { f($0, .ok) }
        all[0] = f(.captivePortal, .info)
        all[2] = f(.dnsAnswers, .danger)
        all[7] = f(.pageIntegrity, .danger)
        let result = VerdictRules.decide(all, network: net, connected: true)
        XCTAssertEqual(result.verdict, .careful)
        XCTAssertFalse(result.findings.contains { $0.status == .danger })
    }

    func testOffline() {
        XCTAssertEqual(VerdictRules.decide([], network: net, connected: false).verdict, .offline)
    }
}
