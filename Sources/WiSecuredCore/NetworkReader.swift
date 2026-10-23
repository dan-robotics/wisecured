import Foundation
import CoreWLAN
import Network
import SystemConfiguration
import CNetInfo

// Reads the Mac's OWN connection: its Wi-Fi association, its route to the router, the router's
// hardware address from the Mac's address table, and the DNS servers the network handed out.
// Nothing here scans other devices or reads anyone else's traffic.

public struct WiFiInfo: Sendable {
    public var interfaceName: String?
    /// nil without Location permission (macOS hides Wi-Fi names from apps without it).
    public var ssid: String?
    public var bssid: String?
    public var security: String
    public var channel: String?
    public var rssi: Int?
}

public struct SavedNetwork: Sendable, Hashable {
    public var ssid: String
    public var security: String
}

public struct PathInfo: Sendable {
    public var status: String
    /// True on phone hotspots: iOS (and most Android) tell the Mac the link costs money.
    public var isExpensive: Bool
    public var isConstrained: Bool
    public var interfaces: [String]

    public init(_ path: NWPath) {
        switch path.status {
        case .satisfied: status = "connected"
        case .unsatisfied: status = "no connection"
        case .requiresConnection: status = "waiting for connection"
        @unknown default: status = "unknown"
        }
        isExpensive = path.isExpensive
        isConstrained = path.isConstrained
        interfaces = path.availableInterfaces.map { iface in
            let kind: String
            switch iface.type {
            case .wifi: kind = "Wi-Fi"
            case .wiredEthernet: kind = "Ethernet"
            case .cellular: kind = "cellular"
            case .loopback: kind = "loopback"
            case .other: kind = "other"
            @unknown default: kind = "unknown"
            }
            return "\(iface.name) (\(kind))"
        }
    }
}

public struct RouterInfo: Sendable {
    public var gateway: String?
    public var interface: String?
    public var routerMAC: String?
    /// Other IP addresses in the Mac's address table that claim the router's hardware address.
    public var otherIPsWithRouterMAC: [String]
    /// How many entries the address table showed this process (0 = hidden from the app).
    public var addressTableEntries: Int
}

public enum NetworkReader {
    // MARK: Wi-Fi

    public static func wifi() -> WiFiInfo {
        guard let iface = CWWiFiClient.shared().interface() else {
            return WiFiInfo(interfaceName: nil, ssid: nil, bssid: nil, security: "no Wi-Fi interface", channel: nil, rssi: nil)
        }
        let channel = iface.wlanChannel().map { "\($0.channelNumber) (\(bandName($0.channelBand.rawValue)))" }
        return WiFiInfo(interfaceName: iface.interfaceName, ssid: iface.ssid(), bssid: iface.bssid(),
                        security: securityName(iface.security().rawValue), channel: channel, rssi: iface.rssiValue())
    }

    /// Networks saved on this Mac (System Settings › Wi-Fi › Known networks).
    public static func savedNetworks() -> [SavedNetwork] {
        guard let profiles = CWWiFiClient.shared().interface()?.configuration()?.networkProfiles else { return [] }
        return profiles.array.compactMap { item in
            guard let profile = item as? CWNetworkProfile, let ssid = profile.ssid else { return nil }
            return SavedNetwork(ssid: ssid, security: securityName(profile.security.rawValue))
        }
    }

    /// Feasibility test for phase 3: join a saved network WITHOUT supplying its password.
    /// Changes the Mac's Wi-Fi network — only ever called from an explicit user action.
    public static func tryJoinWithoutPassword(ssid: String) -> String {
        guard let iface = CWWiFiClient.shared().interface() else { return "No Wi-Fi interface." }
        do {
            let found = try iface.scanForNetworks(withName: ssid)
            guard let network = found.max(by: { $0.rssiValue < $1.rssiValue }) else {
                return "\"\(ssid)\" is not in range."
            }
            try iface.associate(to: network, password: nil)
            return "Joined \"\(ssid)\" without a password."
        } catch let error as NSError {
            return "Could not join \"\(ssid)\": \(error.domain) \(error.code) — \(error.localizedDescription)"
        }
    }

    /// Networks the Mac can see right now (read-only scan, takes a few seconds), strongest first.
    /// Names are only visible with Location permission.
    public static func scanNearby() -> (networks: [(ssid: String, rssi: Int)], error: String?) {
        guard let iface = CWWiFiClient.shared().interface() else { return ([], "No Wi-Fi interface.") }
        do {
            let found = try iface.scanForNetworks(withName: nil)
            var best: [String: Int] = [:]
            for network in found {
                let name = network.ssid ?? "(hidden name)"
                best[name] = max(best[name] ?? Int.min, network.rssiValue)
            }
            return (best.map { ($0.key, $0.value) }.sorted { $0.rssi > $1.rssi }, nil)
        } catch let error as NSError {
            return ([], "\(error.domain) \(error.code) — \(error.localizedDescription)")
        }
    }

    /// Feasibility test B for phase 3: ask macOS's own `networksetup` tool to join a saved network
    /// without a password (it may use the password macOS already stores). Changes the Mac's
    /// Wi-Fi network — only ever called from an explicit user action.
    public static func tryJoinViaNetworksetup(ssid: String) -> String {
        guard let name = CWWiFiClient.shared().interface()?.interfaceName else { return "No Wi-Fi interface." }
        let output = run("/usr/sbin/networksetup", ["-setairportnetwork", name, ssid], includeErrors: true)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return output.isEmpty ? "macOS joined \"\(ssid)\" via networksetup (no password given)." : "networksetup: \(output)"
    }

    // MARK: Router + DNS

    public static func router() -> RouterInfo {
        let route = run("/sbin/route", ["-n", "get", "default"])
        let gateway = field(route, "gateway:")
        let interface = field(route, "interface:")
        let table = addressTable()
        guard let gateway else {
            return RouterInfo(gateway: nil, interface: interface, routerMAC: nil, otherIPsWithRouterMAC: [], addressTableEntries: table.count)
        }
        let mac = table.first { $0.ip == gateway }?.mac
        let others = mac.map { m in table.filter { $0.mac == m && $0.ip != gateway }.map(\.ip) } ?? []
        return RouterInfo(gateway: gateway, interface: interface, routerMAC: mac, otherIPsWithRouterMAC: others,
                          addressTableEntries: table.count)
    }

    /// DNS servers currently in use (what the network handed out, or what the user set).
    public static func dnsServers() -> [String] {
        guard let store = SCDynamicStoreCreate(nil, "WiSecured" as CFString, nil, nil),
              let dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any]
        else { return [] }
        return dns["ServerAddresses"] as? [String] ?? []
    }

    /// Diagnostic for the probe: what the address-table tool returns to THIS process, with its
    /// exit status and error text (both are hidden in normal use).
    public static func addressTableDiagnostic(gateway: String?) -> String {
        let all = runDetailed("/usr/sbin/arp", ["-an"])
        let lines = all.output.split(separator: "\n")
        var text = "arp -an → exit \(all.status), \(lines.count) line(s); first: \(lines.first.map(String.init) ?? "(empty)")"
        if let gateway {
            let one = runDetailed("/usr/sbin/arp", ["-n", gateway])
            let out = one.output.trimmingCharacters(in: .whitespacesAndNewlines)
            text += "\narp -n \(gateway) → exit \(one.status): \(out.isEmpty ? "(empty)" : out)"
        }
        let direct = directAddressTable()
        let routerFound = gateway.map { g in direct.entries.contains { $0.ip == g } } ?? false
        text += "\nin-app kernel read → \(direct.error.map { "refused (errno \($0))" } ?? "ok"), "
            + "\(direct.total) record(s), \(direct.entries.count) with address; router \(routerFound ? "FOUND" : "not found")"
        return text
    }

    /// The address table read inside this process (no helper tool), via CNetInfo.
    public static func directAddressTable() -> (entries: [(ip: String, mac: String)], total: Int, error: Int32?) {
        var buffer = [wn_arp_entry](repeating: wn_arp_entry(), count: 512)
        var total: Int32 = 0
        let count = buffer.withUnsafeMutableBufferPointer { wn_arp_entries($0.baseAddress, Int32($0.count), &total) }
        guard count >= 0 else { return ([], Int(total), -count) }
        let entries = buffer.prefix(Int(count)).map { entry -> (ip: String, mac: String) in
            let ip = withUnsafeBytes(of: entry.ip) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
            let mac = withUnsafeBytes(of: entry.mac) { $0.map { String(format: "%02x", $0) }.joined(separator: ":") }
            return (ip, mac)
        }
        return (entries, Int(total), nil)
    }

    /// The current Wi-Fi security as CWSecurity's raw value (nil without Wi-Fi / Location).
    public static func securityRaw() -> Int? {
        guard let iface = CWWiFiClient.shared().interface(), iface.ssid() != nil else { return nil }
        return iface.security().rawValue
    }

    /// The system proxy settings as apps see them (System Settings › Network › Details › Proxies).
    public static func systemProxies() -> (entries: [Checks.ProxyEntry], autoConfigURL: String?, autoDiscovery: Bool) {
        guard let d = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else { return ([], nil, false) }
        func on(_ key: String) -> Bool { (d[key] as? Int ?? 0) == 1 }
        var entries: [Checks.ProxyEntry] = []
        for (enable, host, port, kind) in [("HTTPEnable", "HTTPProxy", "HTTPPort", "Web proxy (HTTP)"),
                                           ("HTTPSEnable", "HTTPSProxy", "HTTPSPort", "Secure web proxy (HTTPS)"),
                                           ("SOCKSEnable", "SOCKSProxy", "SOCKSPort", "SOCKS proxy")] where on(enable) {
            if let h = d[host] as? String, !h.isEmpty { entries.append(Checks.ProxyEntry(kind: kind, host: h, port: d[port] as? Int ?? 0)) }
        }
        let pac = on("ProxyAutoConfigEnable") ? (d["ProxyAutoConfigURLString"] as? String) : nil
        return (entries, pac, on("ProxyAutoDiscoveryEnable"))
    }

    // MARK: Routing table + interfaces (read-only)

    /// IPv4 routes, read inside the app (same data as `netstat -rn`).
    public static func routes() -> [Checks.RouteEntry] {
        var buffer = [wn_route](repeating: wn_route(), count: 2048)
        var total: Int32 = 0
        let count = buffer.withUnsafeMutableBufferPointer { wn_routes($0.baseAddress, Int32($0.count), &total) }
        guard count > 0 else { return [] }
        return buffer.prefix(Int(count)).map { r in
            Checks.RouteEntry(destination: cString(r.dest), gateway: cString(r.gateway), interface: cString(r.ifname), flags: UInt32(r.flags))
        }
    }

    /// Router hardware address from the in-app address-table read (the `arp` tool sees nothing
    /// when started by an app on macOS 27), plus other IPs claiming the same address.
    public static func routerIdentity(router: String?) -> (mac: String?, others: [String], reachable: Set<String>) {
        let table = directAddressTable().entries
        let reachable = Set(table.map(\.ip))
        guard let router, let mac = table.first(where: { $0.ip == router })?.mac else { return (nil, [], reachable) }
        return (mac, table.filter { $0.mac == mac && $0.ip != router }.map(\.ip), reachable)
    }

    /// Interface names, and each interface's IPv4 address + netmask.
    public static func interfaces() -> (names: Set<String>, ipv4: [String: (address: String, mask: String)]) {
        var names = Set<String>(), ipv4: [String: (String, String)] = [:]
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return ([], [:]) }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            let name = String(cString: entry.pointee.ifa_name)
            names.insert(name)
            if let addr = entry.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET), let mask = entry.pointee.ifa_netmask {
                ipv4[name] = (ipv4String(addr), ipv4String(mask))
            }
            cursor = entry.pointee.ifa_next
        }
        return (names, ipv4)
    }

    /// Tunnel interfaces carrying real IPv4 routes (corporate VPN clients, Tailscale, WireGuard, …). macOS'
    /// own idle utun interfaces carry none and are ignored.
    public static func vpnInterfaces(in routes: [Checks.RouteEntry]) -> [String] {
        let tunnels = routes.filter { r in
            ["utun", "ppp", "ipsec", "tun", "wg"].contains { r.interface.hasPrefix($0) }
                && !r.destination.hasPrefix("224.") && !r.destination.hasPrefix("255.") && !r.destination.hasPrefix("169.254")
        }
        return Array(Set(tunnels.map(\.interface))).sorted()
    }

    /// DNS servers configured for one interface's network service (what that network handed
    /// out), so a VPN's DNS doesn't hide the café's. Falls back to the global list.
    public static func dnsServers(forInterface name: String?) -> [String] {
        guard let name, let store = SCDynamicStoreCreate(nil, "WiSecured" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/IPv4" as CFString) as? [String]
        else { return dnsServers() }
        for key in keys {
            guard let ipv4 = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  ipv4["InterfaceName"] as? String == name else { continue }
            let dnsKey = key.replacingOccurrences(of: "/IPv4", with: "/DNS")
            if let dns = SCDynamicStoreCopyValue(store, dnsKey as CFString) as? [String: Any],
               let servers = dns["ServerAddresses"] as? [String], !servers.isEmpty {
                return servers
            }
        }
        return dnsServers()
    }

    /// DNS servers set by hand on this Mac for one interface's service (Setup: keys — System
    /// Settings or a script such as a DNS auto-switcher). Empty when the network's are used.
    public static func dnsSetOnMac(forInterface name: String?) -> [String] {
        guard let name, let store = SCDynamicStoreCreate(nil, "WiSecured" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/IPv4" as CFString) as? [String]
        else { return [] }
        for key in keys {
            guard let ipv4 = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  ipv4["InterfaceName"] as? String == name else { continue }
            let setupKey = key.replacingOccurrences(of: "State:", with: "Setup:").replacingOccurrences(of: "/IPv4", with: "/DNS")
            if let dns = SCDynamicStoreCopyValue(store, setupKey as CFString) as? [String: Any] {
                return dns["ServerAddresses"] as? [String] ?? []
            }
        }
        return []
    }

    static func ipv4String(_ sa: UnsafeMutablePointer<sockaddr>) -> String {
        sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
            var addr = sin.pointee.sin_addr
            var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &addr, &text, socklen_t(INET_ADDRSTRLEN))
            return String(decoding: text.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }
    }

    static func cString<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
    }

    // MARK: Helpers

    /// Like `run`, but keeps error text and returns the exit status too.
    static func runDetailed(_ executable: String, _ arguments: [String]) -> (output: String, status: Int32) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return ("could not start: \(error.localizedDescription)", -1) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (String(decoding: data, as: UTF8.self), process.terminationStatus)
    }

    /// The Mac's own IP → hardware address table (`arp -an`), MACs normalised to two-digit octets.
    static func addressTable() -> [(ip: String, mac: String)] {
        run("/usr/sbin/arp", ["-an"]).split(separator: "\n").compactMap { line in
            // "? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]"
            guard let open = line.firstIndex(of: "("), let close = line.firstIndex(of: ")"),
                  let atRange = line.range(of: " at ") else { return nil }
            let ip = String(line[line.index(after: open)..<close])
            let rest = line[atRange.upperBound...]
            let raw = rest.split(separator: " ").first.map(String.init) ?? ""
            guard raw.contains(":") else { return nil }   // "(incomplete)"
            let mac = raw.split(separator: ":").map { $0.count == 1 ? "0\($0)" : String($0) }.joined(separator: ":")
            return (ip, mac.lowercased())
        }
    }

    static func field(_ text: String, _ name: String) -> String? {
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix(name) {
                return trimmed.dropFirst(name.count).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// Runs a system tool by full path with fixed arguments (no shell) and returns its output.
    static func run(_ executable: String, _ arguments: [String], includeErrors: Bool = false) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = includeErrors ? pipe : FileHandle.nullDevice
        do { try process.run() } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    static func bandName(_ raw: Int) -> String {
        switch raw {
        case 1: return "2.4 GHz"
        case 2: return "5 GHz"
        case 3: return "6 GHz"
        default: return "unknown band"
        }
    }

    /// CWSecurity raw values → readable names (raw values avoid SDK-specific case spellings).
    static func securityName(_ raw: Int) -> String {
        switch raw {
        case 0: return "Open (no password)"
        case 1: return "WEP (broken)"
        case 2: return "WPA Personal"
        case 3: return "WPA/WPA2 Personal"
        case 4: return "WPA2 Personal"
        case 5: return "Personal"
        case 6: return "Dynamic WEP (broken)"
        case 7: return "WPA Enterprise"
        case 8: return "WPA/WPA2 Enterprise"
        case 9: return "WPA2 Enterprise"
        case 10: return "Enterprise"
        case 11: return "WPA3 Personal"
        case 12: return "WPA3 Enterprise"
        case 13: return "WPA2/WPA3 Personal"
        case 14: return "Enhanced Open (OWE)"
        case 15: return "Open / Enhanced Open"
        default: return "unknown"
        }
    }
}
