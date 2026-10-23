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

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if let report = monitor.report {
                tags(report.network)
                Text(report.reason)
                    .font(.system(size: 12.5))
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 9).fill(Theme.row))
                if !monitor.locationAllowed { locationBanner }
                meta(report)
                checks(report)
            } else {
                Text("Checking this network…").font(.callout).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 80)
            }
            if let tools, let report = monitor.report, let group = tools.group(for: report.network) {
                myTools(group, kind: tools.classify(report.network))
            }
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
                Text("WiSecured").font(.caption).foregroundStyle(.secondary)
                Spacer()
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
            if n.isExpensive { tag("Phone hotspot", .secondary) }
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

    private var locationBanner: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "location.slash").foregroundStyle(Color(nsColor: Theme.yellow))
            VStack(alignment: .leading, spacing: 4) {
                Text("Allow Location so WiSecured can read the Wi-Fi name and security type. Your location is never used or stored.")
                    .font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                Button("Open Location settings") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.link).font(.system(size: 12))
            }
        }
    }

    private func meta(_ report: Report) -> some View {
        HStack {
            Text("\(report.findings.count) checks · \(report.date.formatted(date: .omitted, time: .shortened))")
            Spacer()
            if monitor.settings.watchSeconds > 0 { Text("Router watched every \(monitor.settings.watchSeconds) s") }
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
                    if expanded == finding.id { details(finding) }
                }
                .padding(.horizontal, 10).padding(.vertical, 7)
                if finding.id != report.findings.last?.id { Divider().opacity(0.6) }
            }
        }
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.row))
    }

    private func details(_ f: Finding) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            labelled("Seen", f.seen)
            labelled("Means", f.meaning)
            if !f.action.isEmpty { labelled("Do", f.action) }
            if f.id == .routingHealth, f.status == .warn, let clean = tools?.cleanRoutes {
                Button("Run \"\(clean.title)\" in Terminal…") { actions.runTool(clean) }
                    .buttonStyle(.bordered).controlSize(.small).padding(.top, 2)
            }
        }
        .padding(.leading, 17)
        .textSelection(.enabled)
    }

    /// My tools for the network type the Mac is on (all groups are in the right-click menu).
    private func myTools(_ group: ToolGroup, kind: NetworkKind) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("My tools · \(group.title)").font(.system(size: 12, weight: .semibold))
                Spacer()
                Text("this network: \(kind.rawValue)").font(.system(size: 10.5)).foregroundStyle(.secondary)
            }
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
