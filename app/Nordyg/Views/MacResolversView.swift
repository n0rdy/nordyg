import SwiftUI

/// "How this Mac resolves names": the resolvers macOS uses, in order, with
/// split-DNS rules and Bonjour scopes, and which one answers a given name.
struct MacResolversSheet: View {
    @EnvironmentObject var model: AppModel
    @ObservedObject var monitor: MacDNSMonitor
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let plan = monitor.plan
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("How this Mac resolves names").font(.title3.weight(.semibold))
                    Text("What every app on this Mac uses. Updates by itself when a VPN connects or the network changes.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            .padding(16)
            Divider()
            if !monitor.available {
                Text("This version of macOS did not share its resolver list, so only the resolvers in the resolver menu are known.")
                    .foregroundStyle(.secondary).padding(16)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        if let at = monitor.changedAt {
                            Label(at.formatted(date: .omitted, time: .shortened) + ": the configuration changed", systemImage: "arrow.triangle.2.circlepath")
                                .font(.callout).foregroundStyle(.orange)
                        }
                        summary(plan)
                        group(plan.splitRules.isEmpty ? "For all domains, in this order" : "For all other domains, in this order") {
                            ForEach(Array(plan.defaults.enumerated()), id: \.offset) { i, r in
                                ForEach(r.nameservers, id: \.self) { ns in
                                    resolverRow(index: i + 1, ns: ns, plan: plan, note: r.isSupplemental ? "added by a VPN or an app" : nil)
                                }
                            }
                        }
                        if !plan.splitRules.isEmpty {
                            group("Only for some names (split DNS)") {
                                ForEach(Array(plan.splitRules.enumerated()), id: \.offset) { _, r in
                                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                                        Text(verbatim: "*.\(r.domain ?? "")").font(.system(.body, design: .monospaced)).fontWeight(.semibold)
                                        Image(systemName: "arrow.right").foregroundStyle(.tertiary)
                                        Text(r.nameservers.map { plan.describe($0) }.joined(separator: ", "))
                                            .font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                        if !plan.multicast.isEmpty {
                            group("Bonjour, on the local network") {
                                let zones = plan.multicast.compactMap(\.domain)
                                Text(verbatim: zones.count > 2 ? "\(zones.prefix(2).joined(separator: ", ")) and \(zones.count - 2) more reverse zones" : zones.joined(separator: ", "))
                                    .font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                                    .help(zones.joined(separator: "\n"))
                            }
                        }
                        let search = Array(Set(plan.defaults.flatMap(\.searchDomains))).sorted()
                        if !search.isEmpty {
                            group("Search domains") {
                                Text(search.joined(separator: ", ")).font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                                Text("A single-label name like “printer” is tried with these appended.").font(.caption).foregroundStyle(.tertiary)
                            }
                        }
                        Text("Encrypted DNS set up by a profile or an app is not visible here. It shows up as a resolver on this Mac's own addresses, like a VPN or filter app does.")
                            .font(.caption).foregroundStyle(.tertiary)
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(width: 620)
        .frame(minHeight: 320, idealHeight: 440, maxHeight: 680)
        .onAppear {
            monitor.reload(initial: true)
        }
    }

    private func group<C: View>(_ title: String, @ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            content()
        }
    }

    private func resolverRow(index: Int, ns: String, plan: MacDNSPlan, note: String?) -> some View {
        let iface = plan.interface(for: ns)
        return HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(verbatim: "\(index)").foregroundStyle(.tertiary).frame(width: 16, alignment: .trailing)
            Text(ns).font(.system(.body, design: .monospaced)).fontWeight(.semibold).textSelection(.enabled)
            if let iface {
                Text(verbatim: "\(InterfaceNames.display(iface) ?? iface) · \(iface)").foregroundStyle(.secondary)
            }
            if let note { Text(note).font(.caption).foregroundStyle(.tertiary) }
            Spacer()
            Button("Use in Query") { use(ns) }.buttonStyle(.link)
        }
    }

    /// The routing in one or two plain sentences, so nothing has to be typed
    /// to learn where a domain goes.
    private func summary(_ plan: MacDNSPlan) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(plan.splitRules.enumerated()), id: \.offset) { _, r in
                Text(verbatim: "Domains ending in \(r.domain ?? "") go to \(r.nameservers.map { plan.describe($0) }.joined(separator: " or ")).")
            }
            Text(verbatim: everyOther(plan))
            if plan.multicast.contains(where: { $0.domain == "local" }) {
                Text("Names ending in .local stay on the local network (Bonjour).").foregroundStyle(.secondary)
            }
        }
        .font(.callout)
        .card(fill: Color.secondary.opacity(0.08))
    }

    private func everyOther(_ plan: MacDNSPlan) -> String {
        let order = plan.defaults.flatMap(\.nameservers).map { plan.describe($0) }
        let subject = plan.splitRules.isEmpty ? "This Mac sends every domain" : "Every other domain goes"
        switch order.count {
        case 0: return "This Mac has no DNS resolver configured right now."
        case 1: return "\(subject) to \(order[0])."
        default:
            let rest = order.dropFirst().joined(separator: ", then ")
            return "\(subject) to \(order[0]) first, and to \(rest) if that fails."
        }
    }

    private func use(_ ns: String) {
        let addr = SystemResolvers.hostPort(ns, 53)
        model.selected = model.allEndpoints.first { $0.transport == "udp" && $0.address == addr }
            ?? Endpoint(transport: "udp", address: addr, label: "System \(ns)")
        model.mode = .query
        model.severalResolvers = false
        dismiss()
    }
}
