import AppKit
import WiSecuredCore

/// Optional custom tools ("My tools"): buttons that open Terminal and run the owner's own
/// commands, as the owner. The standard build passes none; a build can supply its own at start-up.
/// WiSecured itself never changes a setting or a route: the commands run visibly in Terminal,
/// where any password prompt (sudo) is answered by the user.

public enum NetworkKind: String, Sendable {
    case home = "Home", hotspot = "Hotspot", publicNetwork = "Public Wi-Fi"
}

public struct ToolAction: Sendable, Identifiable {
    public enum Role: Sendable { case cleanRoutes }
    public var id: String { title + command }
    public var title: String
    /// Exactly what Terminal runs (shown to the user before running).
    public var command: String
    public var role: Role?

    public init(_ title: String, _ command: String, role: Role? = nil) {
        self.title = title
        self.command = command
        self.role = role
    }
}

public struct ToolGroup: Sendable, Identifiable {
    public var id: String { title }
    public var title: String
    /// The network type this group is meant for (highlighted when it matches); nil = any.
    public var kind: NetworkKind?
    public var actions: [ToolAction]

    public init(_ title: String, for kind: NetworkKind?, _ actions: [ToolAction]) {
        self.title = title
        self.kind = kind
        self.actions = actions
    }
}

public struct PersonalTools: Sendable {
    public var groups: [ToolGroup]
    /// Decides which kind of network the Mac is on, from WiSecured's own reading.
    public var classify: @Sendable (NetworkContext) -> NetworkKind

    public init(groups: [ToolGroup], classify: @escaping @Sendable (NetworkContext) -> NetworkKind) {
        self.groups = groups
        self.classify = classify
    }

    func group(for context: NetworkContext?) -> ToolGroup? {
        guard let context else { return nil }
        let kind = classify(context)
        return groups.first { $0.kind == kind }
    }

    var cleanRoutes: ToolAction? { groups.flatMap(\.actions).first { $0.role == .cleanRoutes } }
}

/// Runs a command in a new Terminal window after the user confirms it.
@MainActor
enum TerminalRunner {
    static func confirmAndRun(_ action: ToolAction) {
        let confirm = NSAlert()
        confirm.messageText = "Run \"\(action.title)\" in Terminal?"
        confirm.informativeText = "Terminal opens and runs, as you:\n\n\(action.command)\n\nIf it asks for your password (sudo), type it in Terminal."
        confirm.addButton(withTitle: "Run in Terminal")
        confirm.addButton(withTitle: "Cancel")
        NSApp.activate()
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        let escaped = action.command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let source = "tell application \"Terminal\"\nactivate\ndo script \"\(escaped)\"\nend tell"
        var error: NSDictionary?
        NSAppleScript(source: source)?.executeAndReturnError(&error)
        guard let error else { return }

        let failed = NSAlert()
        failed.alertStyle = .warning
        let code = error[NSAppleScript.errorNumber] as? Int ?? 0
        failed.messageText = "Couldn't open Terminal"
        failed.informativeText = code == -1743
            ? "WiSecured isn't allowed to control Terminal. Allow it in System Settings › Privacy & Security › Automation › WiSecured › Terminal, then try again."
            : "\(error[NSAppleScript.errorMessage] as? String ?? "Unknown error") (\(code))"
        failed.runModal()
    }
}
