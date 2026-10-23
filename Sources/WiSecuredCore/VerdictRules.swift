import Foundation

/// Turns the ten findings into one verdict and a one-line reason.
public enum VerdictRules {
    /// While a login page is pending, these checks see the portal, not the internet.
    static let blockedByLoginPage: Set<CheckID> = [.dnsInterception, .dnsAnswers, .dnssec, .certificates, .pageIntegrity]

    /// Applies the login-page rule to the findings, then decides the verdict.
    public static func decide(_ findings: [Finding], network: NetworkContext, connected: Bool) -> (findings: [Finding], verdict: Verdict, reason: String) {
        guard connected else { return (findings, .offline, "No network connection.") }

        var adjusted = findings
        let loginPending = findings.first { $0.id == .captivePortal }?.status == .info
        if loginPending {
            for i in adjusted.indices where blockedByLoginPage.contains(adjusted[i].id) && adjusted[i].status >= .warn {
                adjusted[i] = Finding(adjusted[i].id, .unknown, summary: "After login",
                                      seen: "Skipped: the login page answers in place of the internet right now.",
                                      meaning: "This check runs again once you've finished the login page.")
            }
            return (adjusted, .careful, "This network shows a login page. Finish it in your browser; the checks then run again.")
        }

        let dangers = adjusted.filter { $0.status == .danger }
        if !dangers.isEmpty {
            let names = dangers.map { $0.id.title.lowercased() }.joined(separator: ", ")
            return (adjusted, .danger, "Tampering found (\(names)). Don't log in to anything on this network.")
        }
        let warnings = adjusted.filter { $0.status == .warn }
        if let first = warnings.first {
            let more = warnings.count > 1 ? " (+\(warnings.count - 1) more)" : ""
            return (adjusted, .careful, "\(first.id.title): \(first.summary.lowercased())\(more). \(first.action)")
        }
        let unknown = adjusted.filter { $0.status == .unknown }
        if unknown.count >= 5 {
            return (adjusted, .careful, "Most checks couldn't run yet — no internet, or still connecting.")
        }
        return (adjusted, .safe, "No tampering found on \(network.displayName).")
    }
}
