import AppKit
import Combine
import SwiftUI
import WiSecuredCore

public enum Edition: Sendable { case `public`, personal }

/// App entry point (called from Sources/WiSecured/main.swift).
public enum WiSecuredApp {
    /// `tools` = optional custom tools; `aboutNote` = an optional extra line for About.
    /// The standard build passes neither.
    @MainActor
    public static func run(edition: Edition, tools: PersonalTools? = nil, aboutNote: String? = nil) {
        let app = NSApplication.shared
        let delegate = AppDelegate(edition: edition, tools: tools, aboutNote: aboutNote)
        app.delegate = delegate
        app.setActivationPolicy(.accessory)     // menu bar only, no Dock icon
        withExtendedLifetime(delegate) { app.run() }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let edition: Edition
    private let tools: PersonalTools?
    private let aboutNote: String?
    private let settings = AppSettings()
    private var monitor: Monitor?
    private var statusItem: NSStatusItem?
    private let popover = NSPopover()
    private var settingsWindow: NSWindow?
    private var cancellables: Set<AnyCancellable> = []

    init(edition: Edition, tools: PersonalTools?, aboutNote: String?) {
        self.edition = edition
        self.tools = tools
        self.aboutNote = aboutNote
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let monitor = Monitor(settings: settings)
        self.monitor = monitor

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.imagePosition = .imageLeading
        item.button?.target = self
        item.button?.action = #selector(statusItemClicked)
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        statusItem = item

        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: DropdownView(
            monitor: monitor, edition: edition, tools: tools,
            actions: DropdownActions(openSettings: { [weak self] in self?.showSettings() },
                                     quit: { NSApp.terminate(nil) },
                                     runTool: { [weak self] action in self?.runTool(action) })))

        monitor.$report.combineLatest(monitor.$checking, settings.$showNetworkName)
            .receive(on: RunLoop.main)
            .sink { [weak self] report, checking, showName in
                MainActor.assumeIsolated { self?.updateIcon(report, checking: checking, showName: showName) }
            }
            .store(in: &cancellables)
    }

    private func updateIcon(_ report: Report?, checking: Bool, showName: Bool) {
        let verdict: Verdict = report?.verdict ?? .checking
        statusItem?.button?.image = Shield.image(for: verdict, size: 17, tight: true)
        statusItem?.button?.title = showName ? " \(report?.network.displayName ?? "")" : ""
        statusItem?.button?.toolTip = "WiSecured — \(verdict.title)\(report.map { ": \($0.network.displayName)" } ?? "")"
    }

    /// Left-click: the dropdown. Right-click or Control-click: the short menu.
    @objc private func statusItemClicked() {
        let event = NSApp.currentEvent
        if event?.type == .rightMouseUp || event?.modifierFlags.contains(.control) == true {
            showMenu()
        } else {
            togglePopover()
        }
    }

    private func showMenu() {
        popover.performClose(nil)
        guard let item = statusItem else { return }
        item.menu = makeMenu()
        item.button?.performClick(nil)    // opens the menu under the icon
        item.menu = nil                   // so the next left-click opens the dropdown again
    }

    private func makeMenu() -> NSMenu {
        let menu = NSMenu()
        let report = monitor?.report
        let status = report.map { "\($0.verdict.title) — \($0.network.displayName)" } ?? "Checking…"
        let header = NSMenuItem(title: status, action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)
        menu.addItem(.separator())
        menu.addItem(menuItem("Check now", #selector(checkNowFromMenu), "r"))
        if report?.network.interfaceName != nil {
            let trusted = monitor?.isCurrentTrusted == true
            menu.addItem(menuItem(trusted ? "Stop trusting this network" : "Trust this network", #selector(trustFromMenu), ""))
        }
        menu.addItem(menuItem("Settings…", #selector(settingsFromMenu), ","))
        menu.addItem(menuItem("About WiSecured", #selector(aboutFromMenu), ""))
        if let tools, !tools.groups.isEmpty {
            let item = NSMenuItem(title: "My tools", action: nil, keyEquivalent: "")
            let submenu = NSMenu()
            let current = tools.group(for: report?.network)
            for (index, group) in tools.groups.enumerated() {
                if index > 0 { submenu.addItem(.separator()) }
                let title = group.title + (group.id == current?.id ? "  ·  this network" : "")
                let header = NSMenuItem(title: title, action: nil, keyEquivalent: "")
                header.isEnabled = false
                submenu.addItem(header)
                for action in group.actions {
                    let entry = NSMenuItem(title: action.title, action: #selector(toolFromMenu(_:)), keyEquivalent: "")
                    entry.target = self
                    entry.indentationLevel = 1
                    entry.representedObject = ToolBox(action)
                    entry.toolTip = action.command
                    submenu.addItem(entry)
                }
            }
            item.submenu = submenu
            menu.addItem(item)
        }
        menu.addItem(.separator())
        menu.addItem(menuItem("Quit WiSecured", #selector(quitFromMenu), "q"))
        return menu
    }

    private func menuItem(_ title: String, _ action: Selector, _ key: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.target = self
        return item
    }

    @objc private func checkNowFromMenu() { monitor?.checkNow() }
    @objc private func trustFromMenu() { monitor?.toggleTrustCurrent() }

    @objc private func toolFromMenu(_ sender: NSMenuItem) {
        guard let box = sender.representedObject as? ToolBox else { return }
        runTool(box.action)
    }

    private func runTool(_ action: ToolAction) {
        popover.performClose(nil)
        TerminalRunner.confirmAndRun(action)
    }
    @objc private func settingsFromMenu() { showSettings() }
    @objc private func quitFromMenu() { NSApp.terminate(nil) }

    @objc private func aboutFromMenu() {
        NSApp.activate()
        let credits = NSAttributedString(
            string: (aboutNote.map { "\($0)\n" } ?? "") + "Public Wi-Fi, secured.\nChecks whether the network you're on is tampering with your connection. Read-only, local, no telemetry.",
            attributes: [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor])
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "WiSecured",
            .credits: credits,
        ])
    }

    @objc private func togglePopover() {
        guard let button = statusItem?.button else { return }
        if popover.isShown {
            popover.performClose(nil)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    private func showSettings() {
        popover.performClose(nil)
        if settingsWindow == nil {
            let window = NSWindow(contentViewController: NSHostingController(rootView: SettingsView(settings: settings, monitor: monitor!, edition: edition, aboutNote: aboutNote)))
            window.title = "WiSecured Settings"
            window.styleMask = [.titled, .closable, .miniaturizable]
            window.isReleasedWhenClosed = false
            window.center()
            settingsWindow = window
        }
        NSApp.activate()
        settingsWindow?.makeKeyAndOrderFront(nil)
    }
}

/// Carries a ToolAction on an NSMenuItem (representedObject needs a class).
final class ToolBox: NSObject {
    let action: ToolAction
    init(_ action: ToolAction) { self.action = action }
}
