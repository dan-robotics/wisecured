import Foundation
import Network
import os

/// Sends one plain DNS question (type A) over UDP to a given server and reports whether and how
/// it answered. Used by the "DNS answers" check; in the probe it also triggers macOS' Local
/// Network permission, because the network's DNS server is usually on the local network.
public enum DNSProbe {
    public static func queryA(server: String, name: String, timeout: TimeInterval = 3) async -> String {
        let packet = buildQuery(name: name)
        let connection = NWConnection(host: NWEndpoint.Host(server), port: 53, using: .udp)
        let finished = OSAllocatedUnfairLock(initialState: false)

        return await withCheckedContinuation { (continuation: CheckedContinuation<String, Never>) in
            @Sendable func finish(_ result: String) {
                let first = finished.withLock { done -> Bool in
                    if done { return false }
                    done = true
                    return true
                }
                guard first else { return }
                connection.cancel()
                continuation.resume(returning: result)
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: packet, completion: .contentProcessed { error in
                        if let error { finish("send failed: \(error)") }
                    })
                    connection.receiveMessage { data, _, _, error in
                        guard let data, data.count >= 12 else {
                            finish("no answer\(error.map { ": \($0)" } ?? "")")
                            return
                        }
                        let bytes = [UInt8](data)
                        let answers = Int(bytes[6]) << 8 | Int(bytes[7])
                        let rcode = bytes[3] & 0x0f
                        finish("answered: \(answers) record\(answers == 1 ? "" : "s"), result code \(rcode)\(rcode == 0 ? " (OK)" : "")")
                    }
                case .waiting(let error):
                    finish("blocked or waiting: \(error)")
                case .failed(let error):
                    finish("failed: \(error)")
                default:
                    break
                }
            }
            connection.start(queue: DispatchQueue(label: "io.github.dan-robotics.WiSecured.dns"))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                finish("no answer within \(Int(timeout)) s")
            }
        }
    }

    /// Minimal DNS query: header (id, recursion desired, 1 question) + QNAME + type A + class IN.
    static func buildQuery(name: String) -> Data {
        var data = Data([0x57, 0x53, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in name.split(separator: ".") {
            data.append(UInt8(label.utf8.count))
            data.append(contentsOf: label.utf8)
        }
        data.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01])
        return data
    }
}
