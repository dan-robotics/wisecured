import AppKit
import SwiftUI
import WiSecuredCore

struct DropdownActions {
    var openSettings: () -> Void
    var quit: () -> Void
    var runTool: (ToolAction) -> Void
}

/// The menu bar dropdown (layout from the approved mockup).
struct DropdownView: View {
    @ObservedObject var monitor: Monitor
    let edition: Edition
    let tools: PersonalTools?
    let actions: DropdownActions
    @State private var expanded: CheckID?
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if !monitor.locationAllowed { locationBanner }
            if let report = monitor.report {
                tags(report.network)
                Text(report.reason)
                    .font(.system(size: 12.5))
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 9).fill(Theme.row))
                if let message = monitor.automationMessage {
                    Text(message).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                if report.finding(.captivePortal)?.status == .info, monitor.settings.secureProfileCreated != nil { secureDNSLoginHint }
                meta(report)
                checks(report)
            } else {
                Text("Checking this network…").font(.callout).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 80)
            }
            if let tools, let report = monitor.report {
                let group = tools.group(for: report.network)
                if group != nil || !monitor.toolStatus.isEmpty {
                    myTools(group, kind: tools.classify(report.network))
                }
            }
            hotspotBar
            Button(action: monitor.checkNow) {
                Text(monitor.checking ? "Checking…" : "Check now")
                    .font(.system(size: 13.5, weight: .semibold))
                    .frame(maxWidth: .infinity, minHeight: 34)
            }
            .buttonStyle(.borderedProminent)
            .tint(Theme.accent)
            .disabled(monitor.checking)
            Divider()
            HStack {
                if monitor.report?.network.interfaceName != nil {
                    Button(monitor.isCurrentTrusted ? "Trusted ✓" : "Trust this network…") { monitor.toggleTrustCurrent() }
                        .buttonStyle(.borderless)
                        .foregroundStyle(Theme.accent)
                        .help(monitor.isCurrentTrusted ? "Click to stop trusting this network" : "Mark this as your home or office network")
                } else {
                    Text("WiSecured").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if monitor.report != nil {
                    Button(copied ? "Copied ✓" : "Copy report") { copyReport() }
                        .buttonStyle(.borderless)
                        .help("Copies this check as text — network names, hardware IDs and local addresses masked")
                }
                Button("Settings…", action: actions.openSettings).buttonStyle(.borderless)
                Button("Quit", action: actions.quit).buttonStyle(.borderless)
            }
            .font(.system(size: 12.5))
        }
        .padding(16)
        .frame(width: 380)
    }

    private var header: some View {
        let verdict = monitor.checking && monitor.report == nil ? .checking : (monitor.report?.verdict ?? .checking)
        return HStack(spacing: 12) {
            Image(nsImage: Shield.image(for: verdict, size: 40))
            VStack(alignment: .leading, spacing: 2) {
                Text(verdict.title)
                    .font(.system(size: 19, weight: .bold, design: .rounded))
                    .foregroundStyle(Color(nsColor: Theme.color(verdict)))
                Text(monitor.report?.network.displayName ?? "—").font(.system(size: 13, weight: .semibold))
            }
            Spacer()
            if monitor.checking { ProgressView().controlSize(.small) }
        }
    }

    private func tags(_ n: NetworkContext) -> some View {
        HStack(spacing: 6) {
            if let kind = monitor.currentKindLabel { tag(kind, kind == "Trusted" ? Theme.accent : .secondary) }
            if n.isWiFi {
                let open = n.securityRaw == 0
                tag(open ? "Open · no password" : n.security, open ? Color(nsColor: Theme.yellow) : .secondary)
            } else if n.interfaceName != nil {
                tag("Wired", .secondary)
            }
            tag(n.vpnOn ? "VPN on" : "VPN off", n.vpnOn ? Theme.accent : .secondary)
        }
    }

    private func tag(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 11.5, weight: .medium))
            .foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(Color.primary.opacity(0.07)))
    }

    /// P3: hard to miss — three checks can't work without it.
    private var locationBanner: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "location.slash.fill").font(.system(size: 18)).foregroundStyle(Color(nsColor: Theme.yellow))
            VStack(alignment: .leading, spacing: 6) {
                Text("Allow Location — 3 checks need it").font(.system(size: 13, weight: .semibold))
                Text("macOS only shows the Wi-Fi name and security type to apps with Location permission. Without it, Wi-Fi security, Known network and the network's name can't be checked. WiSecured never uses or stores your location.")
                    .font(.system(size: 11.5)).fixedSize(horizontal: false, vertical: true)
                Button("Open Location settings…") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.borderedProminent).tint(Color(nsColor: Theme.yellow)).foregroundStyle(.black).controlSize(.small)
                Text("Turn on WiSecured in the list, then come back here.").font(.system(size: 10.5)).foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9).strokeBorder(Color(nsColor: Theme.yellow), lineWidth: 1.5))
    }

    private var secureDNSLoginHint: some View {
        Text("If the login page doesn't appear, Secure DNS may be blocking it: switch Secure DNS off in System Settings › VPN & Filters while you log in, then back on.")
            .font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }

    private func copyReport() {
        guard let report = monitor.report else { return }
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
        let names = monitor.networks.compactMap(\.ssid) + [monitor.settings.hotspotSSID, monitor.previousSSID].compactMap { $0 }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(ReportText.make(report, version: version, names: names), forType: .string)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
    }

    private func meta(_ report: Report) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text("\(report.findings.count) checks · \(report.date.formatted(date: .omitted, time: .shortened))")
                Spacer()
                if monitor.settings.watchSeconds > 0 { Text("Router watched every \(monitor.settings.watchSeconds) s") }
            }
            if let provider = report.provider {
                Text("Internet provider: \(provider.labelWithCountry)").lineLimit(1).truncationMode(.tail)
                    .help("Owner of this network's public address, from \(provider.registry)")
            }
        }
        .font(.system(size: 11)).foregroundStyle(.secondary)
    }

    private func checks(_ report: Report) -> some View {
        VStack(spacing: 0) {
            ForEach(report.findings) { finding in
                VStack(alignment: .leading, spacing: 6) {
                    Button {
                        withAnimation(.easeOut(duration: 0.15)) { expanded = expanded == finding.id ? nil : finding.id }
                    } label: {
                        HStack(spacing: 9) {
                            Circle().fill(Theme.color(finding.status)).frame(width: 8, height: 8)
                            Text(finding.id.title).font(.system(size: 12.5, weight: .semibold))
                            Spacer(minLength: 6)
                            Text(finding.summary)
                                .font(.system(size: 12))
                                .foregroundStyle(finding.status >= .warn && finding.status != .unknown ? Theme.color(finding.status) : .secondary)
                                .lineLimit(1)
                            Image(systemName: expanded == finding.id ? "chevron.up" : "chevron.down")
                                .font(.system(size: 9, weight: .semibold)).foregroundStyle(.tertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("\(finding.id.title): \(finding.summary)")
                    if expanded == finding.id { details(finding, report) }
                }
                .padding(.horizontal, 10).padding(.vertical, 7)
                if finding.id != report.findings.last?.id { Divider().opacity(0.6) }
            }
        }
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.row))
    }

    private func details(_ f: Finding, _ report: Report) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            labelled("Seen", f.seen)
            labelled("Means", f.meaning)
            if !f.action.isEmpty { labelled("Do", f.action) }
            if f.id == .routingHealth, f.status == .warn, let clean = tools?.cleanRoutes {
                Button("Run \"\(clean.title)\" in Terminal…") { actions.runTool(clean) }
                    .buttonStyle(.bordered).controlSize(.small).padding(.top, 2)
            }
            if f.id == .dnsAnswers, !report.rewrites.isEmpty {
                HStack(spacing: 6) {
                    Button(monitor.lookingUp ? "Looking up…" : "Who owns this?") { monitor.whoOwns() }
                        .buttonStyle(.bordered).controlSize(.small).disabled(monitor.lookingUp)
                        .help("Asks the internet registry (HTTPS, Apple's built-in certificate authorities only) who owns \(report.rewrites.joined(separator: ", ")) and this network's own address")
                    if !report.owners.isEmpty {
                        Text(report.owners.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value.labelWithCountry)" }.joined(separator: "; "))
                            .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2)
                    }
                }
                .padding(.top, 2)
            }
            if f.id == .dnsAnswers || f.id == .networkDNS, let device = report.filterCandidate {
                Button("This is my filter (\(device.address))") { monitor.confirmFilter(device) }
                    .buttonStyle(.bordered).controlSize(.small).padding(.top, 2)
                    .help("Remembers \(device.address) with its hardware ID \(device.mac) as your DNS filter on this network. A different device at that address later turns red.")
            }
        }
        .padding(.leading, 17)
        .textSelection(.enabled)
    }

    /// Phase 3: switch to the user's hotspot (prominent when the network isn't safe) and back.
    @ViewBuilder
    private var hotspotBar: some View {
        let verdict = monitor.report?.verdict
        if monitor.isOnHotspot, monitor.previousSSID != nil || !monitor.trustedSwitchTargets.isEmpty {
            if let back = monitor.previousSSID {
                Button { monitor.switchBack() } label: {
                    Label("Back to \"\(back)\"", systemImage: "arrow.uturn.backward").frame(maxWidth: .infinity, minHeight: 26)
                }
                .buttonStyle(.bordered).disabled(monitor.switching)
            }
            ForEach(monitor.trustedSwitchTargets, id: \.self) { ssid in
                Button { monitor.switchTo(ssid) } label: {
                    Label("Switch to \"\(ssid)\"", systemImage: "wifi").frame(maxWidth: .infinity, minHeight: 22)
                }
                .buttonStyle(.bordered).disabled(monitor.switching)
            }
        } else if let hotspot = monitor.settings.hotspotSSID, !monitor.isOnHotspot {
            let urgent = verdict == .danger || verdict == .careful
            Button { monitor.switchToHotspot() } label: {
                Label(urgent ? "Switch to my hotspot" : "Switch to \"\(hotspot)\"", systemImage: "personalhotspot")
                    .frame(maxWidth: .infinity, minHeight: 26)
            }
            .buttonStyle(.borderedProminent)
            .tint(verdict == .danger ? Color(nsColor: Theme.red) : (urgent ? Color(nsColor: Theme.yellow) : Theme.accent.opacity(0.75)))
            .foregroundStyle(verdict == .careful ? Color.black : Color.white)
            .disabled(monitor.switching)
        } else if monitor.settings.hotspotSSID == nil, verdict == .danger {
            Button("Set up your phone hotspot in Settings to switch in one click…", action: actions.openSettings)
                .buttonStyle(.link).font(.system(size: 12))
        }
        if monitor.switching {
            HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Switching…").font(.system(size: 12)) }
        } else if let message = monitor.switchMessage {
            Text(message).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    /// My tools for the network type the Mac is on (all groups are in the right-click menu),
    /// with the edition's status lines on top.
    private func myTools(_ group: ToolGroup?, kind: NetworkKind) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("My tools" + (group.map { " · \($0.title)" } ?? "")).font(.system(size: 12, weight: .semibold))
                Spacer()
                Text("this network: \(kind.rawValue)").font(.system(size: 10.5)).foregroundStyle(.secondary)
            }
            ForEach(monitor.toolStatus) { line in
                HStack(alignment: .firstTextBaseline, spacing: 7) {
                    Circle().fill(Theme.color(line.level)).frame(width: 7, height: 7)
                    Text(line.title).font(.system(size: 11.5, weight: .semibold))
                    Text(line.text).font(.system(size: 11.5)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            if let group {
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 6), GridItem(.flexible(), spacing: 6)], spacing: 6) {
                    ForEach(group.actions) { action in
                        Button { actions.runTool(action) } label: {
                            Text(action.title).font(.system(size: 12)).frame(maxWidth: .infinity, minHeight: 22)
                        }
                        .buttonStyle(.bordered)
                        .help(action.command)
                    }
                }
                Text("Opens Terminal and runs your script as you — you confirm first.")
                    .font(.system(size: 10.5)).foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.row))
    }

    private func labelled(_ label: String, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(label).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary).frame(width: 40, alignment: .leading)
            Text(text).font(.system(size: 11.5)).fixedSize(horizontal: false, vertical: true)
        }
    }
}
