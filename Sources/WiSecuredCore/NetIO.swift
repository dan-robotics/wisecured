import Foundation
import Network
import Security
import os

/// The network side of the checks. Every "test the network itself" connection is pinned to the
/// physical interface (Wi-Fi or Ethernet), so a VPN or split-VPN routes can't hide the network
/// WiSecured is judging. Reference lookups (encrypted DoH) may use any route: they are
/// authenticated, so the path can't change them. Nothing here changes any system setting.
public enum NetIO {
    // MARK: Plain DNS over UDP

    public static func dns(server: String, name: String, type: UInt16 = DNSMessage.typeA,
                           via interfaceType: NWInterface.InterfaceType?, timeout: TimeInterval = 3) async -> (answered: Bool, outcome: DNSOutcome) {
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        if let interfaceType { parameters.requiredInterfaceType = interfaceType }
        let connection = NWConnection(host: NWEndpoint.Host(server), port: 53, using: parameters)
        let packet = DNSMessage.query(name: name, type: type, id: UInt16.random(in: 1...0xfffe))
        let gate = OnceGate()

        return await withCheckedContinuation { (continuation: CheckedContinuation<(Bool, DNSOutcome), Never>) in
            @Sendable func finish(_ answered: Bool, _ outcome: DNSOutcome) {
                guard gate.first() else { return }
                connection.cancel()
                continuation.resume(returning: (answered, outcome))
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: packet, completion: .contentProcessed { error in
                        if let error { finish(false, .error("send failed: \(error)")) }
                    })
                    connection.receiveMessage { data, _, _, _ in
                        guard let data else { finish(false, .noAnswer); return }
                        finish(true, DNSOutcome(DNSMessage.parse(data)))
                    }
                case .failed(let error): finish(false, .error("\(error)"))
                case .waiting(let error): finish(false, .error("\(error)"))
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { finish(false, .noAnswer) }
        }
    }

    // MARK: Encrypted DNS (DoH, RFC 8484) — the reference the network can't change

    /// Reached by IP, not by name: networks (and DNS filters such as Pi-hole) often block the
    /// names dns.quad9.net / cloudflare-dns.com. Both certificates are valid for these IPs.
    /// Quad9 9.9.9.9 = threat blocking + DNSSEC, no ECS · Cloudflare 1.1.1.2 = malware blocking +
    /// DNSSEC · Google 8.8.8.8 = DNSSEC. Certificates valid for the IPs (checked 2026-10-23).
    public static let quad9DoH = URL(string: "https://9.9.9.9/dns-query")!
    public static let cloudflareDoH = URL(string: "https://1.1.1.2/dns-query")!
    public static let googleDoH = URL(string: "https://8.8.8.8/dns-query")!

    public static func doh(name: String, endpoint: URL, timeout: TimeInterval = 5) async -> DNSOutcome {
        var request = URLRequest(url: endpoint, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = DNSMessage.query(name: name, id: 0)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]   // the reference goes direct, never via a system proxy
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        do {
            let (data, response) = try await session.data(for: request)
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard code == 200 else { return .error("HTTP \(code)") }
            return DNSOutcome(DNSMessage.parse(data))
        } catch {
            return .error(error.localizedDescription)
        }
    }

    // MARK: Plain HTTP (the network can see and change it — that's what we test)

    public struct HTTPResult: Sendable {
        public var status: Int
        public var headers: [String: String]
        public var body: String
    }

    public static func httpGet(host: String, path: String, via interfaceType: NWInterface.InterfaceType?,
                               timeout: TimeInterval = 6) async -> HTTPResult? {
        let parameters = NWParameters.tcp
        parameters.preferNoProxies = true   // test the network itself, not a configured proxy (reported by its own check)
        if let interfaceType { parameters.requiredInterfaceType = interfaceType }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: 80, using: parameters)
        let request = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: WiSecured\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        let gate = OnceGate()
        let buffer = DataBuffer()

        let raw: Data? = await withCheckedContinuation { (continuation: CheckedContinuation<Data?, Never>) in
            @Sendable func finish(_ data: Data?) {
                guard gate.first() else { return }
                connection.cancel()
                continuation.resume(returning: data)
            }
            @Sendable func receive() {
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                    if let data { buffer.append(data) }
                    if isComplete || error != nil || buffer.count > 262_144 { finish(buffer.data) } else { receive() }
                }
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
                        if error != nil { finish(nil) } else { receive() }
                    })
                case .failed, .waiting: finish(nil)
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { finish(buffer.count > 0 ? buffer.data : nil) }
        }
        guard let raw, let split = raw.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: raw[..<split.lowerBound], as: UTF8.self)
        var body = Data(raw[split.upperBound...])
        let lines = head.components(separatedBy: "\r\n")
        let status = lines.first.flatMap { $0.split(separator: " ").dropFirst().first }.flatMap { Int($0) } ?? 0
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        if headers["transfer-encoding"]?.lowercased().contains("chunked") == true { body = dechunk(body) }
        return HTTPResult(status: status, headers: headers, body: String(decoding: body, as: UTF8.self))
    }

    static func dechunk(_ data: Data) -> Data {
        var out = Data(), rest = data[...]
        while let lineEnd = rest.range(of: Data("\r\n".utf8)) {
            let sizeText = String(decoding: rest[..<lineEnd.lowerBound], as: UTF8.self).split(separator: ";").first ?? ""
            guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16), size > 0 else { break }
            let start = lineEnd.upperBound
            guard rest.distance(from: start, to: rest.endIndex) >= size else { out.append(rest[start...]); break }
            let end = rest.index(start, offsetBy: size)
            out.append(rest[start..<end])
            rest = rest[end...].dropFirst(2)
        }
        return out
    }

    // MARK: TLS certificate check (connects, inspects the certificate, sends nothing)

    public static func tlsProbe(host: String, via interfaceType: NWInterface.InterfaceType?, timeout: TimeInterval = 6) async -> Checks.CertReading {
        let tls = NWProtocolTLS.Options()
        let result = CertBox(host: host)
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            result.inspect(sec_trust_copy_ref(trust).takeRetainedValue())
            complete(true)   // let the handshake finish; the verdict comes from our own evaluation
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.preferNoProxies = true
        if let interfaceType { parameters.requiredInterfaceType = interfaceType }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: 443, using: parameters)
        let gate = OnceGate()

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            @Sendable func finish(_ error: String?) {
                guard gate.first() else { return }
                if let error { result.fail(error) }
                connection.cancel()
                continuation.resume()
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(nil)
                case .failed(let error): finish("\(error)")
                case .waiting(let error): finish("\(error)")
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { finish("timeout") }
        }
        return result.reading
    }

    /// Apple's built-in root certificates (not ones added on this Mac by a company or app).
    static let builtInRoots: Set<Data> = {
        var anchors: CFArray?
        guard SecTrustCopyAnchorCertificates(&anchors) == errSecSuccess, let list = anchors as? [SecCertificate] else { return [] }
        return Set(list.map { SecCertificateCopyData($0) as Data })
    }()

    static let queue = DispatchQueue(label: "io.github.dan-robotics.WiSecured.net", attributes: .concurrent)
}

// MARK: Small thread-safe helpers

/// Lets exactly one of several racing callbacks (answer, error, timeout) finish a request.
final class OnceGate: Sendable {
    private let done = OSAllocatedUnfairLock(initialState: false)
    func first() -> Bool { done.withLock { if $0 { return false }; $0 = true; return true } }
}

final class DataBuffer: Sendable {
    private let storage = OSAllocatedUnfairLock(initialState: Data())
    func append(_ data: Data) { storage.withLock { $0.append(data) } }
    var data: Data { storage.withLock { $0 } }
    var count: Int { storage.withLock { $0.count } }
}

final class CertBox: Sendable {
    private let state: OSAllocatedUnfairLock<Checks.CertReading>

    init(host: String) {
        state = OSAllocatedUnfairLock(initialState: Checks.CertReading(host: host, connected: false, trusted: false, builtInRoot: false, issuer: "?"))
    }

    func inspect(_ trust: SecTrust) {
        let host = state.withLock { $0.host }
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
        var error: CFError?
        let trusted = SecTrustEvaluateWithError(trust, &error)
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        let issuerCert = chain.count > 1 ? chain[1] : chain.first
        let issuer = issuerCert.flatMap { SecCertificateCopySubjectSummary($0) as String? } ?? "?"
        let builtIn = chain.last.map { NetIO.builtInRoots.contains(SecCertificateCopyData($0) as Data) } ?? false
        state.withLock {
            $0.connected = true
            $0.trusted = trusted
            $0.builtInRoot = builtIn
            $0.issuer = issuer
        }
    }

    func fail(_ error: String) { state.withLock { if !$0.connected { $0.error = error } } }

    var reading: Checks.CertReading { state.withLock { $0 } }
}
