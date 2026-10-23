import Foundation

/// Minimal DNS wire format: build one question, read the result code and the IPv4/IPv6
/// addresses in the answer section. Enough for the comparison checks; nothing else.
public enum DNSMessage {
    public static let typeA: UInt16 = 1
    public static let typeAAAA: UInt16 = 28

    public static func query(name: String, type: UInt16 = typeA, id: UInt16 = 0x5753) -> Data {
        var data = Data([UInt8(id >> 8), UInt8(id & 0xff),
                         0x01, 0x00,             // recursion desired
                         0x00, 0x01,             // 1 question
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in name.split(separator: ".") {
            data.append(UInt8(label.utf8.count))
            data.append(contentsOf: label.utf8)
        }
        data.append(contentsOf: [0x00, UInt8(type >> 8), UInt8(type & 0xff), 0x00, 0x01])
        return data
    }

    public struct Response: Sendable, Equatable {
        /// 0 = OK, 2 = SERVFAIL (e.g. DNSSEC failure), 3 = NXDOMAIN.
        public var rcode: Int
        public var addresses: Set<String>
    }

    public static func parse(_ data: Data) -> Response? {
        let b = [UInt8](data)
        guard b.count >= 12 else { return nil }
        let rcode = Int(b[3] & 0x0f)
        let qd = Int(b[4]) << 8 | Int(b[5])
        let an = Int(b[6]) << 8 | Int(b[7])
        var i = 12
        for _ in 0..<qd {
            guard let next = skipName(b, i), next + 4 <= b.count else { return nil }
            i = next + 4
        }
        var addresses = Set<String>()
        for _ in 0..<an {
            guard let next = skipName(b, i), next + 10 <= b.count else { break }
            let type = Int(b[next]) << 8 | Int(b[next + 1])
            let length = Int(b[next + 8]) << 8 | Int(b[next + 9])
            let start = next + 10
            guard start + length <= b.count else { break }
            if type == 1, length == 4 {
                addresses.insert(b[start..<start + 4].map(String.init).joined(separator: "."))
            } else if type == 28, length == 16 {
                let groups = stride(from: start, to: start + 16, by: 2).map { String(Int(b[$0]) << 8 | Int(b[$0 + 1]), radix: 16) }
                addresses.insert(groups.joined(separator: ":"))
            }
            i = start + length
        }
        return Response(rcode: rcode, addresses: addresses)
    }

    /// Skips a (possibly compressed) name; returns the index right after it.
    static func skipName(_ b: [UInt8], _ start: Int) -> Int? {
        var i = start
        while i < b.count {
            let length = Int(b[i])
            if length == 0 { return i + 1 }
            if length & 0xc0 == 0xc0 { return i + 2 <= b.count ? i + 2 : nil }
            i += 1 + length
        }
        return nil
    }
}

/// What a DNS lookup produced, in the terms the checks care about.
public enum DNSOutcome: Sendable, Equatable {
    case addresses(Set<String>)
    /// Deliberately blocked: 0.0.0.0 / :: answers or NXDOMAIN for a name that exists (ad-blockers).
    case blocked
    /// The server answered with an error code (SERVFAIL etc.).
    case failed(rcode: Int)
    case noAnswer
    case error(String)

    public init(_ response: DNSMessage.Response?) {
        guard let response else { self = .noAnswer; return }
        if response.rcode == 3 { self = .blocked; return }
        if response.rcode != 0 { self = .failed(rcode: response.rcode); return }
        let real = response.addresses.subtracting(["0.0.0.0", "0:0:0:0:0:0:0:0", "::"])
        if response.addresses.isEmpty { self = .noAnswer }
        else if real.isEmpty { self = .blocked }
        else { self = .addresses(real) }
    }

    public var label: String {
        switch self {
        case .addresses(let set): return set.sorted().joined(separator: ", ")
        case .blocked: return "blocked (0.0.0.0 / not found)"
        case .failed(let rcode): return "error code \(rcode)"
        case .noAnswer: return "no answer"
        case .error(let text): return text
        }
    }
}
