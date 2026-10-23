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

    init(settings: AppSettings) {
        self.settings = settings
        super.init()
        location.delegate = self
        locationAllowed = Self.allowed(location.authorizationStatus)
        location.requestWhenInUseAuthorization()

        pathMonitor = Self.makePathMonitor { [weak self] update in
            Task { @MainActor in self?.pathChanged(update) }
        }
        settings.$fullCheckMinutes.sink { [weak self] _ in Task { @MainActor in self?.restartTimers() } }.store(in: &cancellables)
        settings.$watchSeconds.sink { [weak self] _ in Task { @MainActor in self?.restartTimers() } }.store(in: &cancellables)
        settings.$reference.dropFirst().sink { [weak self] _ in Task { @MainActor in self?.checkNow() } }.store(in: &cancellables)

        if Bundle.main.bundleURL.pathExtension == "app" {
            Task { _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) }
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
        let checker = Checker(reference: settings.reference)
        let physical = physical, isExpensive = isExpensive
        let probeContext = checker.context(physical: physical, isExpensive: isExpensive)
        let key = Self.key(for: probeContext)
        let baseline = routerBaseline[key]
        Task.detached {
            let report = await checker.run(physical: physical, isExpensive: isExpensive, previousRouterMAC: baseline)
            await MainActor.run { self.finished(report, key: key) }
        }
    }

    private func finished(_ report: Report, key: String) {
        checking = false
        networkKey = key
        if routerBaseline[key] == nil, let mac = report.network.routerMAC { routerBaseline[key] = mac }
        publish(report)
        restartTimers()
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
        let request = UNNotificationRequest(identifier: "wisecured-\(Int(report.date.timeIntervalSince1970))", content: content, trigger: nil)
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
