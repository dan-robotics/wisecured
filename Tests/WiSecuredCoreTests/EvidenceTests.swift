import XCTest
@testable import WiSecuredCore

// 0.5.0: evidence-based verdicts, filter devices, owner lookups (parsing only), Secure DNS
// profile, DNS rules / Proxy Auto decisions, Copy report masking. All simulated — no network.

private func rewrite(_ got: String, name: String = "one.one.one.one") -> Checks.AnchorReading {
    .init(name: name, expected: ["1.1.1.1", "1.0.0.1"], network: .addresses([got]), reference: .addresses(["1.1.1.1", "1.0.0.1"]))
}

private let sky = OwnerInfo(address: "90.207.238.183", label: "Sky UK Limited", network: "SKY-BROADBAND", country: "GB",
                            handles: ["BBH-RIPE", "BSKYB-BROADBAND-MNT"], abuseDomains: ["sky.uk"], registry: "RIPE NCC")
private let skyCustomer = OwnerInfo(address: "2.96.1.1", label: "Sky UK Limited", country: "GB",
                                    handles: ["BSKYB-BROADBAND-MNT"], abuseDomains: ["sky.uk"], registry: "RIPE NCC")
private let hosting = OwnerInfo(address: "203.0.113.66", label: "Some Hosting Ltd", country: "NL",
                                handles: ["HOST-MNT"], abuseDomains: ["hosting.example"], registry: "RIPE NCC")

private func remembered(_ kind: RememberedNetwork.Kind = .trusted) -> RememberedNetwork {
    RememberedNetwork(id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!, ssid: "Home", routerIP: "192.168.1.1",
                      routerMACs: ["aa:aa:aa:aa:aa:01"], accessPoints: [], strongestSecurityRank: 4, lastSecurity: "WPA2 Personal",
                      kind: kind, firstSeen: Date(), lastSeen: Date(), timesSeen: 3)
}
private let pihole = FilterDevice(address: "192.168.1.53", mac: "b8:27:eb:00:00:01",
                                  networkID: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!, networkName: "Home")

final class EvidenceVerdictTests: XCTestCase {
    func testWithoutEvidenceEveryRewriteStaysRed() {
        XCTAssertEqual(Checks.dnsAnswers([rewrite("90.207.238.183")]).status, .danger)
        XCTAssertEqual(Checks.dnsAnswers([rewrite("192.168.1.53")]).status, .danger)
        XCTAssertEqual(Checks.dnsAnswers([rewrite("90.207.238.183")]).summary, "Fake answers (1 of 1)")
    }

    func testOwnProviderFilterIsYellowWithTheOwnerNamed() {
        let e = Checks.DNSEvidence(provider: skyCustomer, owners: ["90.207.238.183": sky], lookupsOn: true)
        let f = Checks.dnsAnswers([rewrite("90.207.238.183")], evidence: e)
        XCTAssertEqual(f.status, .warn)
        XCTAssertEqual(f.summary, "Rewritten by your provider")
        XCTAssertTrue(f.seen.contains("Sky UK Limited"), f.seen)
        XCTAssertFalse(f.meaning.lowercased().contains("culprit"))
    }

    func testOtherOwnerIsRedAndNamed() {
        let e = Checks.DNSEvidence(provider: skyCustomer, owners: ["203.0.113.66": hosting], lookupsOn: true)
        let f = Checks.dnsAnswers([rewrite("203.0.113.66")], evidence: e)
        XCTAssertEqual(f.status, .danger)
        XCTAssertTrue(f.seen.contains("Some Hosting Ltd, NL"), f.seen)
        XCTAssertTrue(f.seen.contains("not this network's internet provider (Sky UK Limited)"), f.seen)
    }

    func testNeverYellowWithoutBothOwners() {
        // Owner known but own provider unknown → can't prove it's the provider → red.
        XCTAssertEqual(Checks.dnsAnswers([rewrite("90.207.238.183")], evidence: .init(owners: ["90.207.238.183": sky])).status, .danger)
        // Provider known, owner unknown → red, and the text offers "Who owns this?".
        let f = Checks.dnsAnswers([rewrite("90.207.238.183")], evidence: .init(provider: skyCustomer, lookupsOn: true))
        XCTAssertEqual(f.status, .danger)
        XCTAssertTrue(f.meaning.contains("Who owns this?"), f.meaning)
        XCTAssertTrue(f.seen.contains("owner unknown"), f.seen)
    }

    func testFilterDeviceGreenOnlyWhenConfirmedOnTrustedNetwork() {
        let confirmed = Checks.DNSEvidence(trustedNetwork: true, devices: ["192.168.1.53": .confirmed(pihole)])
        let green = Checks.dnsAnswers([rewrite("192.168.1.53")], evidence: confirmed)
        XCTAssertEqual(green.status, .ok)
        XCTAssertEqual(green.summary, "Your filter")

        let unconfirmed = Checks.DNSEvidence(trustedNetwork: true, devices: ["192.168.1.53": .unconfirmed])
        XCTAssertEqual(Checks.dnsAnswers([rewrite("192.168.1.53")], evidence: unconfirmed).status, .info)

        let stranger = Checks.DNSEvidence(trustedNetwork: false, devices: ["192.168.1.53": .unconfirmed])
        XCTAssertEqual(Checks.dnsAnswers([rewrite("192.168.1.53")], evidence: stranger).status, .danger)

        let swapped = Checks.DNSEvidence(trustedNetwork: true, devices: ["192.168.1.53": .macChanged(pihole, now: "de:ad:be:ef:00:01")])
        let red = Checks.dnsAnswers([rewrite("192.168.1.53")], evidence: swapped)
        XCTAssertEqual(red.status, .danger)
        XCTAssertTrue(red.seen.contains("de:ad:be:ef:00:01"), red.seen)
    }

    func testBlockedByConfirmedFilterIsGreen() {
        let readings: [Checks.AnchorReading] = [
            .init(name: "a.root-servers.net", expected: ["198.41.0.4"], network: .addresses(["198.41.0.4"]), reference: .addresses(["198.41.0.4"])),
            .init(name: "dns.google", expected: ["8.8.8.8"], network: .blocked, reference: .addresses(["8.8.8.8"])),
        ]
        let e = Checks.DNSEvidence(trustedNetwork: true, devices: ["192.168.1.53": .confirmed(pihole)])
        let f = Checks.dnsAnswers(readings, server: "192.168.1.53", evidence: e)
        XCTAssertEqual(f.status, .ok)
        XCTAssertEqual(f.summary, "Your filter · others match")
        // Same on a network that isn't trusted: stays blue, as before.
        XCTAssertEqual(Checks.dnsAnswers(readings, server: "192.168.1.53", evidence: .init(devices: e.devices)).status, .info)
    }

    func testMixedRewritesTakeTheWorst() {
        let e = Checks.DNSEvidence(trustedNetwork: true, provider: skyCustomer, owners: ["90.207.238.183": sky],
                                   devices: ["192.168.1.53": .confirmed(pihole)], lookupsOn: true)
        let f = Checks.dnsAnswers([rewrite("192.168.1.53", name: "dns.google"), rewrite("90.207.238.183")], evidence: e)
        XCTAssertEqual(f.status, .warn)
    }

    func testRewrittenAddresses() {
        XCTAssertEqual(Checks.rewrittenAddresses([rewrite("90.207.238.183"), rewrite("1.1.1.1")]), ["90.207.238.183"])
    }
}

final class FilterDeviceTests: XCTestCase {
    func testMatch() {
        let home = remembered()
        XCTAssertEqual(FilterDevices.match(address: "192.168.1.53", mac: "B8:27:EB:00:00:01", network: home, devices: [pihole]), .confirmed(pihole))
        XCTAssertEqual(FilterDevices.match(address: "192.168.1.53", mac: "de:ad:be:ef:00:01", network: home, devices: [pihole]),
                       .macChanged(pihole, now: "de:ad:be:ef:00:01"))
        XCTAssertEqual(FilterDevices.match(address: "192.168.1.53", mac: nil, network: home, devices: [pihole]), .unconfirmed, "unreadable MAC proves nothing")
        var other = remembered(); other.id = UUID()
        XCTAssertEqual(FilterDevices.match(address: "192.168.1.53", mac: "b8:27:eb:00:00:01", network: other, devices: [pihole]), .unconfirmed,
                       "confirmed on another network only")
        XCTAssertEqual(FilterDevices.match(address: "192.168.1.53", mac: "b8:27:eb:00:00:01", network: nil, devices: [pihole]), .unconfirmed)
    }

    func testNetworkDNS() {
        // P2: set by hand, off this network, no answer → yellow.
        let off = Checks.networkDNS(servers: ["172.20.10.1"], router: "172.20.10.1", setOnMac: ["192.168.1.53"],
                                    offNetwork: .init(address: "192.168.1.53", answered: false))
        XCTAssertEqual(off.status, .warn)
        XCTAssertEqual(off.summary, "DNS not on this network")
        // Reachable (e.g. through a VPN) → no warning.
        XCTAssertEqual(Checks.networkDNS(servers: ["172.20.10.1"], router: "172.20.10.1", setOnMac: ["192.168.1.53"],
                                         offNetwork: .init(address: "192.168.1.53", answered: true)).status, .info)
        // Option D.
        let mine = Checks.networkDNS(servers: ["192.168.1.1"], router: "192.168.1.1", setOnMac: ["192.168.1.53"],
                                     devices: ["192.168.1.53": .confirmed(pihole)], trusted: true)
        XCTAssertEqual(mine.status, .ok)
        XCTAssertEqual(mine.summary, "Your filter")
        XCTAssertEqual(Checks.networkDNS(servers: ["192.168.1.1"], router: "192.168.1.1", setOnMac: ["192.168.1.53"],
                                         devices: ["192.168.1.53": .confirmed(pihole)], trusted: false).status, .info)
        XCTAssertEqual(Checks.networkDNS(servers: ["192.168.1.53"], router: "192.168.1.1",
                                         devices: ["192.168.1.53": .macChanged(pihole, now: "de:ad:be:ef:00:01")], trusted: true).status, .danger)
    }

    func testOfficeCountsAsTrusted() {
        let f = Checks.networkMemory(NetworkMemory.assess(NetworkContext(isWiFi: true, ssid: "Home", securityRaw: 4, security: "WPA2 Personal",
                                                                         routerMAC: "aa:aa:aa:aa:aa:01"), records: [remembered(.office)]))
        XCTAssertEqual(f.summary, "Office")
        XCTAssertTrue(RememberedNetwork.Kind.office.isTrustedLike)
        XCTAssertFalse(RememberedNetwork.Kind.publicNetwork.isTrustedLike)
    }

    func testProxyViaVPNIsInfo() {
        let entry = Checks.ProxyEntry(kind: "Web proxy (HTTP)", host: "192.168.77.10", port: 3128)
        XCTAssertEqual(Checks.systemProxy(.init(entries: [entry], autoConfigURL: nil, autoDiscovery: false,
                                                localAddress: "172.20.10.2", localMask: "255.255.255.240")).status, .warn)
        XCTAssertEqual(Checks.systemProxy(.init(entries: [entry], autoConfigURL: nil, autoDiscovery: false,
                                                localAddress: "172.20.10.2", localMask: "255.255.255.240", vpnOn: true)).status, .info)
    }
}

final class OwnerTests: XCTestCase {
    /// Shaped like RIPE's real answer for 90.207.238.183 (2026-10-23).
    static let skyJSON = #"""
    {"handle":"90.207.238.128 - 90.207.238.191","name":"SKY-BROADBAND","country":"GB",
     "remarks":[{"description":["Sky UK Limited"]}],
     "entities":[
      {"handle":"BBH-RIPE","roles":["administrative","technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Sky UK Broadband Hostmaster"],["email",{},"text","abuse@sky.uk"]]]},
      {"handle":"BSKYB-BROADBAND-MNT","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","BSKYB-BROADBAND-MNT"]]]},
      {"handle":"BBH-RIPE","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Sky UK Broadband Hostmaster"],["email",{},"text","abuse@sky.uk"]]]}
     ]}
    """#

    func testParseRDAP() throws {
        let info = try XCTUnwrap(Owners.parseRDAP(Data(Self.skyJSON.utf8), address: "90.207.238.183", registry: "RIPE NCC"))
        XCTAssertEqual(info.label, "Sky UK Limited")
        XCTAssertEqual(info.network, "SKY-BROADBAND")
        XCTAssertEqual(info.country, "GB")
        XCTAssertEqual(info.handles, ["BBH-RIPE", "BSKYB-BROADBAND-MNT"])
        XCTAssertEqual(info.abuseDomains, ["sky.uk"])
        XCTAssertNil(Owners.parseRDAP(Data("not json".utf8), address: "1.2.3.4", registry: "x"))
    }

    func testLabelSkipsHandles() throws {
        let json = #"{"name":"NET-X","entities":[{"handle":"MNT-X","roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","MNT-X"]]]},{"handle":"N1","roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","Example NOC"]]]}]}"#
        XCTAssertEqual(try XCTUnwrap(Owners.parseRDAP(Data(json.utf8), address: "5.5.5.5", registry: "RIPE NCC")).label, "Example NOC")
        // Lower-case maintainer names are handles too; "… Abuse" roles aren't a name.
        let lower = #"{"name":"NET_Y","entities":[{"handle":"mnt-xx-example-1","roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","mnt-xx-example-1"]]]},{"handle":"N2","roles":["administrative"],"vcardArray":["vcard",[["fn",{},"text","Example Admin"]]]},{"handle":"N3","roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Example Abuse"]]]}]}"#
        XCTAssertEqual(try XCTUnwrap(Owners.parseRDAP(Data(lower.utf8), address: "5.5.5.6", registry: "RIPE NCC")).label, "Example Admin")
    }

    func testSameProvider() {
        XCTAssertTrue(Owners.sameProvider(sky, skyCustomer))
        XCTAssertFalse(Owners.sameProvider(sky, hosting))
        // Similar names alone are not proof.
        let lookalike = OwnerInfo(address: "5.5.5.5", label: "Sky UK Limited", handles: ["OTHER-MNT"], abuseDomains: ["other.example"])
        XCTAssertFalse(Owners.sameProvider(sky, lookalike))
    }

    func testFreeMailIsNotEvidence() throws {
        let json = #"{"entities":[{"handle":"A1","roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Someone"],["email",{},"text","x@gmail.com"]]]}]}"#
        XCTAssertEqual(try XCTUnwrap(Owners.parseRDAP(Data(json.utf8), address: "5.5.5.5", registry: "RIPE NCC")).abuseDomains, [])
    }

    func testRegistries() {
        XCTAssertEqual(Owners.registry(for: "90.207.238.183"), .ripe)
        XCTAssertEqual(Owners.registry(for: "8.8.8.8"), .arin)
        XCTAssertEqual(Owners.registry(for: "1.1.1.1"), .apnic)
        XCTAssertEqual(Owners.registry(for: "200.1.1.1"), .lacnic)
        XCTAssertEqual(Owners.registry(for: "41.1.1.1"), .afrinic)
        XCTAssertNil(Owners.registry(for: "192.168.1.1"))
        XCTAssertNil(Owners.registry(for: "100.100.100.100"), "Tailscale / CGNAT")
        XCTAssertNil(Owners.registry(for: "not an ip"))
        XCTAssertTrue(Owners.isPublicIPv4("90.207.238.183"))
        XCTAssertFalse(Owners.isPublicIPv4("192.0.2.53"))
        XCTAssertFalse(Owners.isPublicIPv4("172.20.10.1"))
    }
}

final class ReferenceAndProfileTests: XCTestCase {
    func testNewReferences() {
        XCTAssertEqual(Checker.Reference.adguard.address, "94.140.14.14")
        XCTAssertEqual(Checker.Reference.dns4eu.address, "86.54.11.1")
        XCTAssertEqual(Checker.Reference.dns4eu.dohCertificateName, "protective.joindns4.eu")
        XCTAssertNil(Checker.Reference.adguard.dohCertificateName)
        XCTAssertEqual(Checker.Reference.adguard.fallbackOrder, [.adguard, .quad9, .cloudflare, .google])
        XCTAssertEqual(Checker.Reference.dns4eu.doh.absoluteString, "https://86.54.11.1/dns-query")
    }

    func testProfile() throws {
        let data = SecureDNSProfile.make(provider: .quad9, skipNetworks: ["Home", " ", "Home"], skipDomains: ["*.corp.example", "intranet.local"],
                                         bundleID: "io.example.App")
        let plist = try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        XCTAssertEqual(plist["PayloadIdentifier"] as? String, "io.example.App.secure-dns")
        XCTAssertEqual(plist["PayloadType"] as? String, "Configuration")
        let dns = try XCTUnwrap((plist["PayloadContent"] as? [[String: Any]])?.first)
        XCTAssertEqual(dns["PayloadType"] as? String, "com.apple.dnsSettings.managed")
        let settings = try XCTUnwrap(dns["DNSSettings"] as? [String: Any])
        XCTAssertEqual(settings["DNSProtocol"] as? String, "HTTPS")
        XCTAssertEqual(settings["ServerURL"] as? String, "https://dns.quad9.net/dns-query")
        XCTAssertEqual(settings["ServerAddresses"] as? [String], ["9.9.9.9", "149.112.112.112"])
        let rules = try XCTUnwrap(dns["OnDemandRules"] as? [[String: Any]])
        XCTAssertEqual(rules.count, 3)
        XCTAssertEqual(rules[0]["Action"] as? String, "Disconnect")
        XCTAssertEqual(rules[0]["SSIDMatch"] as? [String], ["Home"])
        let params = try XCTUnwrap((rules[1]["ActionParameters"] as? [[String: Any]])?.first)
        XCTAssertEqual(params["Domains"] as? [String], ["corp.example", "intranet.local"])
        XCTAssertEqual(rules[2]["Action"] as? String, "Connect")
        // Nothing to skip → just "Connect".
        let plain = try XCTUnwrap(PropertyListSerialization.propertyList(from: SecureDNSProfile.make(provider: .dns4eu, skipNetworks: [], skipDomains: [], bundleID: "x"), format: nil) as? [String: Any])
        let plainDNS = try XCTUnwrap((plain["PayloadContent"] as? [[String: Any]])?.first)
        XCTAssertEqual((plainDNS["OnDemandRules"] as? [[String: Any]])?.count, 1)
        XCTAssertEqual(SecureDNSProfile.domains(from: "a.example, b.example\nc.example"), ["a.example", "b.example", "c.example"])
    }
}

final class AutomationTests: XCTestCase {
    func testDNSRules() {
        let home = remembered()
        let rules: [UUID: DNSRule] = [home.id: .custom(["192.168.1.53"])]
        XCTAssertEqual(Automation.desiredDNS(record: home, rules: rules), ["192.168.1.53"])
        XCTAssertEqual(Automation.desiredDNS(record: nil, rules: rules), [], "unknown network → its own DNS")
        var other = remembered(); other.id = UUID()
        XCTAssertEqual(Automation.desiredDNS(record: other, rules: rules), [])
        XCTAssertFalse(Automation.dnsDiffers(current: ["1.1.1.1", "8.8.8.8"], desired: ["8.8.8.8", "1.1.1.1"]))
        XCTAssertTrue(Automation.dnsDiffers(current: ["192.168.1.53"], desired: []))
        XCTAssertEqual(Automation.validAddresses("192.168.1.53, 2001:db8::1; rm -rf x 999.1.1.1"), ["192.168.1.53"],
                       "junk dropped (the ; stuck to the IPv6 makes it invalid too)")
        XCTAssertEqual(Automation.validAddresses("192.168.1.53 2001:db8::1"), ["192.168.1.53", "2001:db8::1"])
    }

    func testProxyAuto() {
        XCTAssertNil(Automation.proxyWanted(mode: .notManaged, kind: .office, workVPN: true))
        XCTAssertEqual(Automation.proxyWanted(mode: .auto, kind: .office, workVPN: false), true)
        XCTAssertEqual(Automation.proxyWanted(mode: .auto, kind: .trusted, workVPN: true), true)
        XCTAssertEqual(Automation.proxyWanted(mode: .auto, kind: .publicNetwork, workVPN: false), false)
        XCTAssertEqual(Automation.proxyWanted(mode: .auto, kind: nil, workVPN: false), false)
        XCTAssertEqual(Automation.proxyWanted(mode: .off, kind: .office, workVPN: true), false)
        let entries = [Checks.ProxyEntry(kind: "Web proxy (HTTP)", host: "192.168.77.10", port: 3128)]
        XCTAssertTrue(Automation.proxyIsOn(host: "192.168.77.10", port: 3128, entries: entries))
        XCTAssertFalse(Automation.proxyIsOn(host: "192.168.77.10", port: 8080, entries: entries))
    }

    func testWorkVPNIgnoresTailscale() {
        XCTAssertFalse(Automation.workVPNUp(vpnInterfaces: ["utun4"], ipv4: ["utun4": ("100.101.102.103", "255.255.255.255")]))
        XCTAssertTrue(Automation.workVPNUp(vpnInterfaces: ["utun4", "utun7"], ipv4: ["utun4": ("100.101.102.103", "255.255.255.255"),
                                                                                    "utun7": ("10.212.134.20", "255.255.255.255")]))
        XCTAssertFalse(Automation.workVPNUp(vpnInterfaces: [], ipv4: [:]))
    }

    func testReportMasking() {
        let text = "Home router 192.168.1.1 (aa:bb:cc:dd:ee:ff) and 10.0.0.5, 172.20.10.1; Sky 90.207.238.183 on \"Home\""
        let masked = ReportText.mask(text, names: ["Home"])
        XCTAssertFalse(masked.contains("Home"))
        XCTAssertFalse(masked.contains("aa:bb:cc"))
        XCTAssertFalse(masked.contains("192.168.1.1"))
        XCTAssertFalse(masked.contains("10.0.0.5"))
        XCTAssertFalse(masked.contains("172.20.10.1"))
        XCTAssertTrue(masked.contains("90.207.238.183"), "public evidence stays")
    }
}
