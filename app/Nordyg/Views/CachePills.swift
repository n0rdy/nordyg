import AppKit
import SwiftUI

/// Pill showing how old a resolver's copy is, with a button to find out.
struct CacheAgePill: View {
    @EnvironmentObject var model: AppModel
    var message: Message
    var question: Question

    var body: some View {
        switch model.cacheAge(of: message, question: question) {
        case .unknown:
            Button("check cache age") { model.fetchAuthoritative(for: question) }
                .buttonStyle(.link)
                .font(.caption)
                .help(Glossary.cacheUnknown)
        case .checking:
            Meta(text: "checking cache age…", help: Glossary.cacheChecking)
        case .fresh:
            Meta(text: "not cached", help: Glossary.cacheFresh)
        case .cached(let s):
            Meta(text: "in cache for \(age(s))", help: Glossary.cacheAge(s))
        case .differs:
            Pill(text: "differs from authoritative", icon: "exclamationmark.triangle.fill", color: .orange, help: Glossary.cacheDiffers)
        }
    }

    func age(_ s: Int) -> String {
        if s < 60 { return "\(s) s" }
        if s < 3600 { return "\(s / 60) min" }
        if s < 86400 { return String(format: "%.1f h", Double(s) / 3600) }
        return String(format: "%.1f d", Double(s) / 86400)
    }
}

struct StalePill: View {
    var body: some View { Pill(text: "stale", icon: "exclamationmark.arrow.circlepath", color: .orange, help: Glossary.stale) }
}

/// What this Mac's own resolver returns, next to what Nordyg got.
struct SystemViewPill: View {
    @EnvironmentObject var model: AppModel
    var system: [String]?
    var answers: [String]
    var name: String = ""

    var body: some View {
        if let system {
            let overlap = !Set(system).isDisjoint(with: Set(answers))
            if overlap {
                // Agreement is the normal case: say it quietly.
                Meta(text: "your Mac sees the same", help: Glossary.systemView(system, overlap: true))
            } else {
                // Say which resolver the Mac asked, and open the full picture on click.
                let asked = model.macDNS.plan.resolver(for: name).flatMap {
                    $0.resolver.nameservers.first.map { model.macDNS.plan.describe($0) }
                }
                Button {
                    model.showMacResolvers = true
                } label: {
                    Pill(
                        text: (system.isEmpty ? "your Mac gets no answer" : "your Mac sees something else")
                            + (asked.map { ", it asks \($0)" } ?? ""),
                        icon: "desktopcomputer", color: .orange,
                        help: Glossary.systemView(system, overlap: false) + "\nClick to see how this Mac resolves names.")
                }
                .buttonStyle(.plain)
            }
        }
    }
}
