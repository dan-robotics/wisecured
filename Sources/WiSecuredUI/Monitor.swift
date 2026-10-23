import AppKit
import Foundation
import Combine
import CoreLocation
import Network
import UserNotifications
import WiSecuredCore

/// Decides when to check and keeps the latest report:
///   - full check when the network changes (after a short settle), every N minutes, or on "Check now"
///   - router identity every few seconds in between
///   - one notification when the verdict turns red for a network
@MainActor
final class Monitor: NSObject, ObservableObject, CLLocationManagerDelegate {
    @Published private(set) var report: Report?
    @Published private(set) var checking = false
    @Published private(set) var locationAllowed = false
    /// Phase 2: networks remembered on this Mac (Application Support, owner-only).
    @Published private(set) var networks: [RememberedNetwork] = []
    private let memoryFile = NetworkMemoryFile(bundleID: Monitor.bundleID)
    /// Option D: filter devices the user confirmed (Application Support, owner-only).
    @Published private(set) var filterDevices: [FilterDevice] = []
    private let filterFile = JSONStore<[FilterDevice]>(bundleID: Monitor.bundleID, file: "filter-devices.json")
    /// "Who owns this?" is running.
    @Published private(set) var lookingUp = false
    /// Last change made by DNS rules / Proxy Auto (or why it couldn't), for the dropdown.
    @Published private(set) var automationMessage: String?
    /// Optional status lines under My tools (only when the edition supplies them).
    @Published private(set) var toolStatus: [ToolStatus] = []
    private var alertSince: [String: Date] = [:]
    private var alerted: Set<String> = []
    private var statusTimer: Timer?
    private var dnsApplied: [(key: String, at: Date)] = []

    static let bundleID = Bundle.main.bundleIdentifier ?? "io.github.dan-robotics.WiSecured"
    let tools: PersonalTools?

    let settings: AppSettings
    private let location = CLLocationManager()
    private var pathMonitor: NWPathMonitor?
    private var physical: (name: String, isWiFi: Bool)?
    private var isExpensive = false
    private var networkKey = ""
    private var routerBaseline: [String: String] = [:]   // network key → router hardware address
    private var notifiedKey: String?
    private var fullTimer: Timer?
    private var watchTimer: Timer?
    private var settleWork: DispatchWorkItem?
    private var cancellables: Set<AnyCancellable> = []
    /// Phase 3: switching to the hotspot and back.
    @Published private(set) var switching = false
    @Published private(set) var switchMessage: String?
    /// P7: where "Back to" returns to — kept in settings, so it survives an app restart.
    var previousSSID: String? { settings.previousSSID }
    private var notificationRouter: NotificationRouter?

    init(settings: AppSettings, tools: PersonalTools? = nil) {
        self.settings = settings
        self.tools = tools
        super.init()
        location.delegate = self
        locationAllowed = Self.allowed(location.authorizationStatus)
        location.requestWhenInUseAuthorization()
        networks = memoryFile.load()
        filterDevices = filterFile.load() ?? []

        pathMonitor = Self.makePathMonitor { [weak self] update in
            Task { @MainActor in self?.pathChanged(update) }
        }
        settings.$fullCheckMinutes.sink { [weak self] _ in Task { @MainActor in self?.restartTimers() } }.store(in: &cancellables)
        settings.$watchSeconds.sink { [weak self] _ in Task { @MainActor in self?.restartTimers() } }.store(in: &cancellables)
        settings.$reference.dropFirst().sink { [weak self] _ in Task { @MainActor in self?.checkNow() } }.store(in: &cancellables)
        settings.$ownerLookups.dropFirst().sink { [weak self] _ in Task { @MainActor in self?.checkNow() } }.store(in: &cancellables)
        if tools?.status != nil {
            statusTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.refreshToolStatus() }
            }
        }

        if Bundle.main.bundleURL.pathExtension == "app" {
            Task { _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) }
            // Red notifications carry a "Switch to my hotspot" button.
            let center = UNUserNotificationCenter.current()
            let action = UNNotificationAction(identifier: NotificationRouter.switchAction, title: "Switch to my hotspot", options: [.foreground])
            center.setNotificationCategories([UNNotificationCategory(identifier: NotificationRouter.redCategory, actions: [action], intentIdentifiers: [])])
            let router = NotificationRouter { [weak self] in Task { @MainActor in self?.switchToHotspot() } }
            notificationRouter = router
            center.delegate = router
        }
    }

    // MARK: Network changes

    struct PathUpdate: Sendable {
        var physical: (name: String, isWiFi: Bool)?
        var isExpensive: Bool
    }

    /// Built outside the main actor: the handler runs on the monitor's own queue (Swift 6 rule).
    nonisolated static func makePathMonitor(_ handler: @escaping @Sendable (PathUpdate) -> Void) -> NWPathMonitor {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { path in
            let iface = path.availableInterfaces.first { $0.type == .wifi || $0.type == .wiredEthernet }
            let physical = path.status == .satisfied ? iface.map { ($0.name, $0.type == .wifi) } : nil
            handler(PathUpdate(physical: physical, isExpensive: path.isExpensive))
        }
        monitor.start(queue: DispatchQueue(label: "io.github.dan-robotics.WiSecured.path"))
        return monitor
    }

    private func pathChanged(_ update: PathUpdate) {
        physical = update.physical
        isExpensive = update.isExpensive
        // Let DHCP, the router entry and DNS settle before judging the new network.
        settleWork?.cancel()
        let work = DispatchWorkItem { [weak self] in MainActor.assumeIsolated { self?.checkNow() } }
        settleWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: work)
    }

    // MARK: Checks

    func checkNow() {
        guard !checking else { return }
        checking = true
        let checker = Checker(reference: settings.reference, lookups: settings.ownerLookups, filterDevices: filterDevices)
        let physical = physical, isExpensive = isExpensive
        let probeContext = checker.context(physical: physical, isExpensive: isExpensive)
        let key = Self.key(for: probeContext)
        let baseline = routerBaseline[key]
        let memory = networks
        let providerKey = "\(probeContext.ssid ?? "-")|\(probeContext.routerMAC ?? probeContext.router ?? "-")"
        Task.detached {
            let report = await checker.run(physical: physical, isExpensive: isExpensive, previousRouterMAC: baseline,
                                           memory: memory, networkKey: providerKey)
            await MainActor.run { self.finished(report, key: key) }
        }
    }

    private func finished(_ report: Report, key: String) {
        checking = false
        networkKey = key
        if routerBaseline[key] == nil, let mac = report.network.routerMAC { routerBaseline[key] = mac }
        publish(report)
        // Remember this network (never one judged "don't trust": an evil twin must not become "known").
        if report.verdict != .danger, report.verdict != .offline {
            networks = NetworkMemory.remembering(report.network, in: networks)
            memoryFile.save(networks)
        }
        restartTimers()
        applyAutomation(report.network)
        refreshToolStatus()
    }

    /// The light watch: re-reads the router's identity and updates that one finding.
    private func watchRouter() {
        guard !checking, var current = report, physical != nil else { return }
        let checker = Checker(reference: settings.reference)
        let context = checker.context(physical: physical, isExpensive: isExpensive)
        let key = Self.key(for: context)
        guard key == networkKey else { checkNow(); return }    // different network: full check
        if routerBaseline[key] == nil, let mac = context.routerMAC { routerBaseline[key] = mac }
        let finding = checker.routerFinding(context, previousMAC: routerBaseline[key])
        guard let index = current.findings.firstIndex(where: { $0.id == .routerIdentity }),
              current.findings[index] != finding else { return }
        current.findings[index] = finding
        current.network = context
        let decided = VerdictRules.decide(current.findings, network: context, connected: true)
        current.findings = decided.findings
        current.verdict = decided.verdict
        current.reason = decided.reason
        publish(current)
    }

    private func publish(_ report: Report) {
        self.report = report
        let alertKey = "\(networkKey)|\(report.findings.filter { $0.status == .danger }.map(\.id.rawValue).joined(separator: ","))"
        if report.verdict == .danger, settings.notifyOnRed, alertKey != notifiedKey {
            notifiedKey = alertKey
            notify(report)
        }
        if report.verdict != .danger { notifiedKey = nil }
    }

    /// One network = its name + router (works for any IP range, mesh access points share it).
    static func key(for context: NetworkContext) -> String {
        "\(context.interfaceName ?? "-")|\(context.ssid ?? "-")|\(context.router ?? "-")"
    }

    // MARK: Network memory (phase 2)

    /// The remembered record for the network the Mac is on now.
    var currentRecord: RememberedNetwork? {
        guard let network = report?.network else { return nil }
        if case .known(let record) = NetworkMemory.assess(network, records: networks).match { return record }
        return nil
    }

    /// "Trusted" / "Office" / "Phone hotspot" / "Public" for the dropdown tag.
    var currentKindLabel: String? {
        guard let network = report?.network, network.interfaceName != nil else { return nil }
        switch currentRecord?.kind {
        case .trusted: return "Trusted"
        case .office: return "Office"
        case .hotspot: return "Phone hotspot"
        case .publicNetwork: return "Public"
        default: return network.isExpensive ? "Phone hotspot" : "Public"
        }
    }

    var isCurrentTrusted: Bool { currentRecord?.kind.isTrustedLike == true }

    /// Trust (or stop trusting) the current network, then re-check so the finding updates.
    func toggleTrustCurrent() {
        guard let network = report?.network else { return }
        if currentRecord == nil { networks = NetworkMemory.remembering(network, in: networks) }
        guard let record = currentRecord else { return }
        setKind(record.id, record.kind.isTrustedLike ? .automatic : .trusted)
    }

    func setKind(_ id: UUID, _ kind: RememberedNetwork.Kind) {
        guard let index = networks.firstIndex(where: { $0.id == id }) else { return }
        networks[index].kind = kind
        memoryFile.save(networks)
        checkNow()
    }

    func forget(_ id: UUID) {
        networks.removeAll { $0.id == id }
        memoryFile.save(networks)
        filterDevices.removeAll { $0.networkID == id }
        filterFile.save(filterDevices)
        settings.dnsRules[id] = nil
        checkNow()
    }

    // MARK: Filter devices (option D)

    /// "This is my filter": remembers the device by address + hardware ID, on this network only.
    func confirmFilter(_ device: LocalDevice) {
        guard let record = currentRecord, record.kind.isTrustedLike else { return }
        filterDevices.removeAll { $0.address == device.address && $0.networkID == record.id }
        filterDevices.append(FilterDevice(address: device.address, mac: device.mac, networkID: record.id, networkName: record.displayName))
        filterFile.save(filterDevices)
        checkNow()
    }

    func removeFilter(_ id: UUID) {
        filterDevices.removeAll { $0.id == id }
        filterFile.save(filterDevices)
        checkNow()
    }

    // MARK: Owner lookups (Q1)

    /// "Who owns this?": looks up every rewritten address (fresh), then re-checks.
    func whoOwns() {
        guard let report, !lookingUp else { return }
        lookingUp = true
        let addresses = report.rewrites
        let via: NWInterface.InterfaceType = report.network.isWiFi ? .wifi : .wiredEthernet
        let providerKey = "\(report.network.ssid ?? "-")|\(report.network.routerMAC ?? report.network.router ?? "-")"
        Task.detached {
            _ = await OwnerLookup.shared.owners(of: addresses, refresh: true)
            _ = await OwnerLookup.shared.provider(key: providerKey, via: via, refresh: true)
            await MainActor.run {
                self.lookingUp = false
                self.checkNow()
            }
        }
    }

    // MARK: DNS rules (L5) + Proxy Auto (S1) — only when switched on

    /// Turning DNS rules on asks to pause a known DNS switcher first (never two things fighting).
    func setDNSRules(_ on: Bool) {
        if let switcher = tools?.dnsSwitcher {
            if on, switcher.isActive() {
                let ask = NSAlert()
                ask.messageText = "Pause \(switcher.name) first?"
                ask.informativeText = "DNS rules and \(switcher.name) would both change your DNS and fight. WiSecured opens Terminal to pause it (reversible: turning DNS rules off offers to resume it)."
                ask.addButton(withTitle: "Pause it in Terminal…")
                ask.addButton(withTitle: "Cancel")
                NSApp.activate()
                guard ask.runModal() == .alertFirstButtonReturn, TerminalRunner.confirmAndRun(switcher.pause) else { return }
            } else if !on, !switcher.isActive() {
                let ask = NSAlert()
                ask.messageText = "Resume \(switcher.name)?"
                ask.informativeText = "DNS rules are off. \(switcher.name) can take over your DNS again."
                ask.addButton(withTitle: "Resume it in Terminal…")
                ask.addButton(withTitle: "Not now")
                NSApp.activate()
                if ask.runModal() == .alertFirstButtonReturn { TerminalRunner.confirmAndRun(switcher.resume) }
            }
        } else if on {
            let ask = NSAlert()
            ask.messageText = "Turn on DNS rules?"
            ask.informativeText = "WiSecured will set your Mac's DNS for the networks you choose, using macOS' networksetup. If another app or script also changes your DNS, switch that off first — WiSecured stops by itself if something keeps changing it back."
            ask.addButton(withTitle: "Turn on")
            ask.addButton(withTitle: "Cancel")
            NSApp.activate()
            guard ask.runModal() == .alertFirstButtonReturn else { return }
        }
        settings.dnsRulesOn = on
        dnsApplied.removeAll()
        if on { checkNow() }
    }

    private func applyAutomation(_ network: NetworkContext) {
        guard let interface = network.interfaceName else { return }
        let record = NetworkMemory.record(for: network, in: networks)
        var changes: [@Sendable () -> String?] = []
        var messages: [String] = []
        let service = NetworkSetup.serviceName(forInterface: interface)

        if settings.dnsRulesOn, let service {
            let desired = Automation.desiredDNS(record: record, rules: settings.dnsRules)
            if Automation.dnsDiffers(current: network.dnsSetOnMac, desired: desired) {
                let key = "\(record?.id.uuidString ?? "-")|\(desired.joined(separator: ","))"
                dnsApplied = dnsApplied.filter { Date().timeIntervalSince($0.at) < 120 }
                if dnsApplied.filter({ $0.key == key }).count >= 3 {
                    settings.dnsRulesOn = false
                    automationMessage = "DNS rules switched off: something else keeps changing your DNS back. Pause it, then turn DNS rules on again."
                    notifyStatus(title: "DNS rules switched off", body: automationMessage ?? "")
                    return
                }
                dnsApplied.append((key, Date()))
                changes.append { NetworkSetup.setDNS(desired, service: service) }
                messages.append(desired.isEmpty ? "DNS set to the network's" : "DNS set to \(desired.joined(separator: ", "))")
            }
        }
        if let service, !settings.proxyHost.isEmpty, settings.proxyPort > 0 {
            let workVPN = Automation.workVPNUp(vpnInterfaces: network.vpnInterfaces, ipv4: NetworkReader.interfaces().ipv4)
            if let wanted = Automation.proxyWanted(mode: settings.proxyMode, kind: record?.kind, workVPN: workVPN) {
                let isOn = Automation.proxyIsOn(host: settings.proxyHost, port: settings.proxyPort, entries: NetworkReader.systemProxies().entries)
                if wanted != isOn {
                    let host = settings.proxyHost, port = settings.proxyPort
                    changes.append { NetworkSetup.setProxy(host: host, port: port, on: wanted, service: service) }
                    messages.append(wanted ? "proxy on (\(record?.kind == .office ? "Office network" : "work VPN"))" : "proxy off")
                }
            }
        }
        guard !changes.isEmpty else { return }
        let text = messages.joined(separator: " · ")
        Task.detached {
            let errors = changes.compactMap { $0() }
            await MainActor.run {
                self.automationMessage = errors.isEmpty ? "WiSecured: \(text)." : "Couldn't change settings: \(errors.joined(separator: "; "))"
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { MainActor.assumeIsolated { self.checkNow() } }
            }
        }
    }

    // MARK: Personal status lines (L1/L2/L4)

    private func refreshToolStatus() {
        guard let status = tools?.status, let network = report?.network else { return }
        let routes = NetworkReader.routes()
        let pinned = routes.filter { $0.isManual && $0.interface == network.interfaceName && !$0.isDefault && $0.gateway == network.router }.count
        let ipv4 = NetworkReader.interfaces().ipv4
        let tunnel = ipv4.keys.contains { $0.hasPrefix("utun") }
        let input = ToolStatusInput(context: checkerContext() ?? network, dnsRulesOn: settings.dnsRulesOn, pinnedRoutes: pinned, tunnelWithIPv4: tunnel)
        Task.detached {
            let lines = await status(input)
            await MainActor.run { self.publishToolStatus(lines) }
        }
    }

    /// The live connection (fresh DNS settings), not the last full check's.
    private func checkerContext() -> NetworkContext? {
        guard physical != nil else { return nil }
        return Checker(reference: settings.reference).context(physical: physical, isExpensive: isExpensive)
    }

    private func publishToolStatus(_ lines: [ToolStatus]) {
        toolStatus = lines
        let now = Date()
        let keys = Set(lines.compactMap(\.alertKey))
        alertSince = alertSince.filter { keys.contains($0.key) }
        alerted = alerted.intersection(keys)
        for line in lines {
            guard let key = line.alertKey else { continue }
            let since = alertSince[key] ?? now
            alertSince[key] = since
            if now.timeIntervalSince(since) >= 10, !alerted.contains(key) {
                alerted.insert(key)
                notifyStatus(title: line.title, body: line.text)
            }
        }
    }

    // MARK: Hotspot (phase 3)

    var isOnHotspot: Bool {
        guard let ssid = report?.network.ssid, let hotspot = settings.hotspotSSID else { return false }
        return ssid == hotspot
    }

    /// Asks, then joins the user's hotspot; remembers where we came from for "Back".
    func switchToHotspot() {
        guard let target = settings.hotspotSSID, !switching, !isOnHotspot else { return }
        let from = WiFiSwitch.currentSSID() ?? report?.network.ssid
        run(to: target, isHotspot: true, from: from)
    }

    /// Asks, then joins the network we were on before the hotspot.
    func switchBack() {
        guard let target = previousSSID, !switching else { return }
        run(to: target, isHotspot: false, from: nil)
    }

    /// P7: Trusted / Office Wi-Fi networks to offer while on the hotspot (newest first, max 3).
    var trustedSwitchTargets: [String] {
        guard isOnHotspot else { return [] }
        let names = networks.filter { $0.kind.isTrustedLike }.sorted { $0.lastSeen > $1.lastSeen }.compactMap(\.ssid)
        var seen = Set<String>()
        return names.filter { $0 != previousSSID && seen.insert($0).inserted }.prefix(3).map { $0 }
    }

    func switchTo(_ ssid: String) {
        guard !switching else { return }
        run(to: ssid, isHotspot: false, from: nil)
    }

    private func run(to target: String, isHotspot: Bool, from: String?) {
        switching = true
        switchMessage = nil
        HotspotSwitcher.confirmAndSwitch(to: target, isHotspot: isHotspot) { [weak self] outcome in
            guard let self else { return }
            self.switching = false
            guard let outcome else { return }
            self.switchMessage = outcome.message
            if outcome.succeeded {
                if isHotspot { self.settings.previousSSID = (from != target) ? from : nil } else { self.settings.previousSSID = nil }
                // The path monitor also notices; this makes sure the new network is checked.
                DispatchQueue.main.asyncAfter(deadline: .now() + 4) { MainActor.assumeIsolated { self.checkNow() } }
            }
        }
    }

    // MARK: Timers

    private func restartTimers() {
        fullTimer?.invalidate()
        watchTimer?.invalidate()
        if settings.fullCheckMinutes > 0 {
            fullTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(settings.fullCheckMinutes * 60), repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.checkNow() }
            }
        }
        if settings.watchSeconds > 0 {
            watchTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(settings.watchSeconds), repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.watchRouter() }
            }
        }
    }

    // MARK: Notifications + Location

    private func notify(_ report: Report) {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return }
        let content = UNMutableNotificationContent()
        content.title = "Don't trust \"\(report.network.displayName)\""
        content.body = report.reason
        content.sound = .default
        if settings.hotspotSSID != nil { content.categoryIdentifier = NotificationRouter.redCategory }
        let request = UNNotificationRequest(identifier: "wisecured-\(Int(report.date.timeIntervalSince1970))", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    /// A plain notification (personal status alerts, DNS rules stopping).
    private func notifyStatus(title: String, body: String) {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: "wisecured-status-\(UUID().uuidString)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let allowed = Self.allowed(manager.authorizationStatus)
        MainActor.assumeIsolated {
            locationAllowed = allowed
            checkNow()
        }
    }

    nonisolated static func allowed(_ status: CLAuthorizationStatus) -> Bool {
        status == .authorizedAlways || status.rawValue == 4
    }
}

/// Handles the "Switch to my hotspot" button on red notifications, and shows notifications
/// while WiSecured's own windows are in front.
final class NotificationRouter: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    static let redCategory = "WISECURED_RED"
    static let switchAction = "SWITCH_HOTSPOT"
    private let onSwitch: @Sendable () -> Void

    init(onSwitch: @escaping @Sendable () -> Void) {
        self.onSwitch = onSwitch
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        if response.actionIdentifier == Self.switchAction { onSwitch() }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }
}
