import AppKit
import Security
import WiSecuredCore

/// Wi-Fi passwords the user typed into WiSecured (their hotspot, and optionally networks to go
/// "back" to), kept in the macOS Keychain under WiSecured's own entry. Never in a file or a log.
enum WiFiPasswords {
    private static var service: String { (Bundle.main.bundleIdentifier ?? "io.github.dan-robotics.WiSecured") + ".wifi" }

    private static func query(_ ssid: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: ssid]
    }

    /// Returns nil on success, otherwise an error message.
    static func save(_ password: String, for ssid: String) -> String? {
        SecItemDelete(query(ssid) as CFDictionary)
        var item = query(ssid)
        item[kSecValueData as String] = Data(password.utf8)
        item[kSecAttrLabel as String] = "WiSecured — Wi-Fi password for \(ssid)"
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        let status = SecItemAdd(item as CFDictionary, nil)
        return status == errSecSuccess ? nil : (SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)")
    }

    static func read(_ ssid: String) -> String? {
        var item = query(ssid)
        item[kSecReturnData as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(item as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func has(_ ssid: String) -> Bool {
        var item = query(ssid)
        item[kSecReturnAttributes as String] = true
        return SecItemCopyMatching(item as CFDictionary, nil) == errSecSuccess
    }

    static func delete(_ ssid: String) { SecItemDelete(query(ssid) as CFDictionary) }

    /// Names of the networks whose passwords WiSecured keeps (no passwords returned).
    static func allSSIDs() -> [String] {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecReturnAttributes as String: true,
                                kSecMatchLimit as String: kSecMatchLimitAll]
        var result: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess, let items = result as? [[String: Any]] else { return [] }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }
}

/// Asks before switching, switches off the main thread, reports the result.
@MainActor
enum HotspotSwitcher {
    /// - Parameters:
    ///   - target: the network to join; `isHotspot` tailors the confirmation text.
    ///   - completion: called on the main actor with the outcome (nil = cancelled).
    static func confirmAndSwitch(to target: String, isHotspot: Bool, completion: @escaping @MainActor (WiFiSwitch.Outcome?) -> Void) {
        let open = WiFiSwitch.isOpen(target)
        var password = WiFiPasswords.read(target)
        if password == nil && !open {
            // No saved password (e.g. "back" to a café network): ask, offer to remember it.
            let ask = NSAlert()
            ask.messageText = "Password for \"\(target)\""
            ask.informativeText = "macOS doesn't share saved Wi-Fi passwords with apps. Type it once; WiSecured can keep it in your Keychain."
            let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
            let remember = NSButton(checkboxWithTitle: "Remember in Keychain", target: nil, action: nil)
            remember.state = .on
            let stack = NSStackView(views: [field, remember])
            stack.orientation = .vertical
            stack.alignment = .leading
            stack.frame = NSRect(x: 0, y: 0, width: 260, height: 54)
            ask.accessoryView = stack
            ask.addButton(withTitle: "Join")
            ask.addButton(withTitle: "Cancel")
            NSApp.activate()
            ask.window.initialFirstResponder = field
            guard ask.runModal() == .alertFirstButtonReturn, !field.stringValue.isEmpty else { completion(nil); return }
            password = field.stringValue
            if remember.state == .on { _ = WiFiPasswords.save(field.stringValue, for: target) }
        } else {
            let confirm = NSAlert()
            confirm.messageText = isHotspot ? "Switch to your hotspot \"\(target)\"?" : "Switch back to \"\(target)\"?"
            confirm.informativeText = "You'll be offline for a few seconds." + (isHotspot ? " On an iPhone, open Settings › Personal Hotspot first so the Mac can see it." : "")
            confirm.addButton(withTitle: "Switch")
            confirm.addButton(withTitle: "Cancel")
            NSApp.activate()
            guard confirm.runModal() == .alertFirstButtonReturn else { completion(nil); return }
        }
        let key = password
        Task.detached {
            let outcome = WiFiSwitch.join(ssid: target, password: key)
            await MainActor.run { completion(outcome) }
        }
    }
}
