import Foundation

/// Option D: a DNS filter device (e.g. a Pi-hole) the user confirmed — its address, its hardware
/// ID (MAC) and the remembered network it was confirmed on. Only that device, on that network,
/// with that hardware ID, turns a local DNS answer green.
public struct FilterDevice: Codable, Sendable, Identifiable, Equatable {
    public var id: UUID
    public var address: String
    public var mac: String
    public var networkID: UUID
    public var networkName: String
    public var added: Date

    public init(id: UUID = UUID(), address: String, mac: String, networkID: UUID, networkName: String, added: Date = Date()) {
        self.id = id; self.address = address; self.mac = mac
        self.networkID = networkID; self.networkName = networkName; self.added = added
    }
}

public enum FilterMatch: Sendable, Equatable {
    /// Same address, same network, same hardware ID.
    case confirmed(FilterDevice)
    /// The confirmed address on that network, but a different (or unreadable) hardware ID.
    case macChanged(FilterDevice, now: String?)
    case unconfirmed
}

public enum FilterDevices {
    /// Pure: how `address` (seen with hardware ID `mac`) relates to the confirmed devices on
    /// the network `record`. An unreadable MAC proves nothing: unconfirmed, never green.
    public static func match(address: String, mac: String?, network record: RememberedNetwork?, devices: [FilterDevice]) -> FilterMatch {
        guard let record, let device = devices.first(where: { $0.address == address && $0.networkID == record.id }) else { return .unconfirmed }
        guard let mac else { return .unconfirmed }
        return mac.lowercased() == device.mac.lowercased() ? .confirmed(device) : .macChanged(device, now: mac)
    }
}

/// A small JSON file in this app's own Application Support folder (owner-only, 700/600).
public final class JSONStore<Value: Codable>: @unchecked Sendable {
    public let url: URL

    public init(bundleID: String, file: String) {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        url = base.appendingPathComponent(bundleID, isDirectory: true).appendingPathComponent(file)
    }

    public func load() -> Value? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(Value.self, from: data)
    }

    public func save(_ value: Value) {
        let folder = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(value) else { return }
        try? data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
