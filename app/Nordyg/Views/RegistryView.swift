import SwiftUI

/// Registration data: who holds the domain, until when, and how it is locked.
struct RegistryView: View {
    var result: RDAPResult

    var body: some View {
        VStack(spacing: 0) {
            StatusStrip {
                Pill(text: result.source.uppercased(), icon: "building.columns", color: .accentColor, mono: true,
                     help: result.source == "rdap" ? "Registration Data Access Protocol (RFC 9083), the JSON successor to WHOIS, mandatory for generic TLDs since January 2025." : "Classic WHOIS over port 43 (RFC 3912). This TLD publishes no RDAP server, so the text was parsed instead.")
                if result.found {
                    if let d = result.expiresInDays {
                        Pill(text: RegistryDates.expiryLabel(d), icon: "calendar", color: d < 0 ? .red : d < 30 ? .orange : .green, mono: true, help: "Time until the registration expires, from the \(result.source.uppercased()) expiration date. Most registrars renew automatically before then.")
                    }
                    if result.dnssec.known {
                        Pill(text: result.dnssec.signed ? "DS at registry" : "no DS at registry", icon: result.dnssec.signed ? "lock.fill" : "lock.open", color: result.dnssec.signed ? .green : .secondary,
                             help: "Whether the registry holds DS records for this delegation, which is what makes the zone's DNSSEC signatures count. The Query and Trace modes validate the actual chain.")
                    }
                    if result.nsMismatch {
                        Pill(text: "NS mismatch", icon: "exclamationmark.triangle.fill", color: .orange, help: "The nameservers on file at the registry differ from the NS records the zone publishes. The registry's list is what the parent zone delegates to. The zone's own list is what resolvers see afterwards. They should agree.")
                    }
                } else {
                    Pill(text: "not registered", icon: "questionmark.circle", color: .orange, help: "The registry has no record for this name. It may be available, reserved, or under a TLD whose registry only answers for exact registered names.")
                }
                Pill(text: RegistryDates.host(result.server), icon: "server.rack", mono: true, help: "The registry server that answered: \(result.server)" + (result.registrarServer.map { "\nRegistrar server followed for contacts: \($0)" } ?? ""))
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if !result.warnings.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(result.warnings, id: \.self) { w in
                                Label(w, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                            }
                        }
                        .card(fill: Color.orange.opacity(0.08))
                    }
                    if result.found {
                        HStack(alignment: .top, spacing: 12) {
                            RegistrarCard(r: result.registrar)
                            DatesCard(result: result)
                        }
                        StatusCard(status: result.status)
                        NameserversCard(result: result)
                        if !result.contacts.isEmpty { ContactsCard(contacts: result.contacts) }
                        if result.dnssec.known { RegistryDNSSECCard(d: result.dnssec) }
                    } else {
                        // Left-aligned like the start panel: a centred box narrower
                        // than the window breaks long names mid-word.
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Not registered", systemImage: "questionmark.circle").font(.title2.weight(.semibold))
                            Text(verbatim: "The registry has no record of \(result.domain), so the name is probably free to register.")
                                .foregroundStyle(.secondary)
                            Text(verbatim: "Asked \(RegistryDates.host(result.server)).").font(.callout).foregroundStyle(.tertiary)
                        }
                        .padding(.vertical, 12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    InfoCard("Raw response", icon: "doc.plaintext", startOpen: false) {
                        Text(result.raw).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    // Notices are the registry's legal boilerplate titles ("Terms of
                    // Use", "Disclaimer"); they live in the raw response.
                    Text(result.bootstrapSource == "embedded"
                         ? "The registry's RDAP server came from the list built into Nordyg, as IANA's live list could not be fetched."
                         : "The registry's RDAP server came from IANA's live list.")
                        .font(.caption).foregroundStyle(.tertiary)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

/// Human time spans and names for the registry view.
enum RegistryDates {
    /// "in 8 years", "in 4 months", "in 12 days", "3 days ago".
    static func span(_ d: Int) -> String {
        let a = abs(d)
        let text: String
        switch a {
        case 730...: text = "\(a / 365) years"
        case 365..<730: text = "1 year"
        case 60..<365: text = "\(Int((Double(a) / 30.4).rounded())) months"
        case 1: text = "1 day"
        default: text = "\(a) days"
        }
        return d < 0 ? "\(text) ago" : "in \(text)"
    }

    static func expiryLabel(_ d: Int) -> String { d < 0 ? "expired \(span(d))" : "expires \(span(d))" }

    /// "https://rdap.verisign.com/com/v1/" → "rdap.verisign.com".
    static func host(_ server: String) -> String { URL(string: server)?.host ?? server }

    /// EPP codes as words, whether RDAP ("client transfer prohibited") or
    /// WHOIS ("clientTransferProhibited") spelled them.
    static func words(_ code: String) -> String {
        guard !code.contains(" ") else { return code.lowercased() }
        var out = ""
        for ch in code {
            if ch.isUppercase, !out.isEmpty { out += " " }
            out += ch.lowercased()
        }
        return out
    }
}

/// A titled card with optional disclosure.
struct InfoCard<Content: View>: View {
    var title: String
    var icon: String
    @State private var open: Bool
    @ViewBuilder var content: Content

    init(_ title: String, icon: String, startOpen: Bool = true, @ViewBuilder content: () -> Content) {
        self.title = title
        self.icon = icon
        self.content = content()
        _open = State(initialValue: startOpen)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(title, systemImage: icon).font(.headline)
                Spacer()
                Button(open ? "Hide" : "Show") { open.toggle() }.buttonStyle(.link).font(.callout)
            }
            if open { content }
        }
        .card()
    }
}

struct RegistrarCard: View {
    var r: RDAPRegistrar
    var body: some View {
        InfoCard("Registrar", icon: "building.2") {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                if let n = r.name { GridRow { Text("Name").foregroundStyle(.secondary); Text(n).fontWeight(.semibold) } }
                if let id = r.ianaId { GridRow { Text("IANA ID").foregroundStyle(.secondary); Text(id).font(.system(.body, design: .monospaced)) } }
                if let u = r.url, let url = URL(string: u.hasPrefix("http") ? u : "https://" + u) { GridRow { Text("Website").foregroundStyle(.secondary); Link(u, destination: url) } }
                if let e = r.abuseEmail { GridRow { Text("Abuse").foregroundStyle(.secondary); Text(e).textSelection(.enabled) } }
                if let p = r.abusePhone { GridRow { Text("Abuse phone").foregroundStyle(.secondary); Text(p).textSelection(.enabled) } }
                if r.name == nil && r.ianaId == nil { GridRow { Text("Not disclosed by this source").foregroundStyle(.secondary) } }
            }
        }
    }
}

struct DatesCard: View {
    var result: RDAPResult
    var body: some View {
        InfoCard("Dates", icon: "calendar") {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                GridRow { Text("Registered").foregroundStyle(.secondary); Text(pretty(result.registered)).font(.system(.body, design: .monospaced)) }
                GridRow {
                    Text("Expires").foregroundStyle(.secondary)
                    HStack(spacing: 8) {
                        Text(pretty(result.expires)).font(.system(.body, design: .monospaced))
                        if let d = result.expiresInDays { Text(verbatim: "(\(RegistryDates.span(d)))").foregroundStyle(d < 30 ? Color.orange : Color.secondary) }
                    }
                }
                GridRow { Text("Updated").foregroundStyle(.secondary); Text(pretty(result.updated)).font(.system(.body, design: .monospaced)) }
                // The database's own timestamp says nothing about the domain.
                ForEach(result.events.filter { !["registration", "expiration", "last changed", "last update of rdap database"].contains($0.action.lowercased()) }, id: \.self) { e in
                    GridRow { Text(e.action.capitalizedFirst).foregroundStyle(.secondary); Text(pretty(e.date)).font(.system(.body, design: .monospaced)) }
                }
            }
        }
    }

    func pretty(_ s: String?) -> String {
        guard let s, !s.isEmpty else { return "—" }
        return ISODate.parse(s)?.formatted(date: .long, time: .omitted) ?? s
    }
}

struct StatusCard: View {
    var status: [RDAPStatus]
    var body: some View {
        InfoCard("Status", icon: "lock.shield") {
            if status.isEmpty {
                Text("No status codes reported.").foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 6) {
                ForEach(status, id: \.code) { s in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Pill(text: RegistryDates.words(s.code), color: color(s.code), mono: true)
                        Text(s.meaning.isEmpty ? "No description available for this code." : s.meaning).font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    func color(_ code: String) -> Color {
        let k = code.lowercased().replacingOccurrences(of: " ", with: "")
        if k.contains("hold") || k.contains("pendingdelete") || k.contains("redemption") || k == "inactive" { return .red }
        if k.contains("prohibited") || k == "locked" { return .green }
        if k.contains("pending") { return .orange }
        return .secondary
    }
}

struct NameserversCard: View {
    var result: RDAPResult
    var body: some View {
        InfoCard("Nameservers", icon: "server.rack") {
            HStack(alignment: .top, spacing: 24) {
                column("At the registry", empty: "none listed", names: result.nameservers, other: result.dnsNameservers)
                column("In the zone (NS records)", empty: "no answer", names: result.dnsNameservers, other: result.nameservers)
            }
        }
    }

    /// One side's list. A name is flagged when the other side has a list
    /// and it is not on it.
    private func column(_ title: String, empty: String, names: [String], other: [String]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            if names.isEmpty { Text(empty).foregroundStyle(.secondary) }
            ForEach(names, id: \.self) { ns in
                let agreed = other.isEmpty || other.contains(ns)
                HStack(spacing: 6) {
                    Image(systemName: agreed ? "checkmark.circle" : "exclamationmark.circle").foregroundStyle(agreed ? Color.green : Color.orange)
                    Text(ns).font(.system(.callout, design: .monospaced))
                }
            }
        }
    }
}

struct ContactsCard: View {
    var contacts: [RDAPContact]
    var body: some View {
        InfoCard("Contacts", icon: "person.2") {
            VStack(alignment: .leading, spacing: 8) {
                let shown = contacts.filter { !Self.isRedacted($0) }
                let hidden = contacts.filter { Self.isRedacted($0) }
                if !hidden.isEmpty {
                    // One line instead of REDACTED repeated per field and role.
                    let privacy = hidden.compactMap(\.org).first { !$0.uppercased().contains("REDACTED") }
                    Text(verbatim: "\(Array(Set(hidden.flatMap(\.roles))).sorted().joined(separator: ", ")): redacted for privacy" + (privacy.map { " (\($0))" } ?? ""))
                        .foregroundStyle(.secondary)
                }
                // Contacts that are the same entity (a privacy service answers
                // for every role) merge; roles sit in one column so the details
                // line up instead of following each capsule's width.
                Grid(alignment: .topLeading, horizontalSpacing: 14, verticalSpacing: 10) {
                    ForEach(Array(Self.merged(shown).enumerated()), id: \.offset) { _, g in
                        GridRow(alignment: .firstTextBaseline) {
                            // One role per line: the column is as wide as its
                            // longest word, not a fixed guess.
                            Text(g.roles.joined(separator: "\n"))
                                .foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                let c = g.contact
                                if let n = c.name, !n.isEmpty { Text(n).fontWeight(.semibold) }
                                if let o = c.org, !o.isEmpty, o != c.name { Text(o) }
                                if let e = c.email, !e.isEmpty {
                                    if e.hasPrefix("http"), let url = URL(string: e) {
                                        Link("contact form", destination: url).help(e)
                                    } else {
                                        Text(e).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                                    }
                                }
                                if let p = c.phone, !p.isEmpty { Text(p).font(.system(.callout, design: .monospaced)).textSelection(.enabled) }
                                if let h = c.handle, !h.isEmpty, c.name == nil && c.org == nil { Text(verbatim: "handle \(h)").foregroundStyle(.secondary) }
                            }
                        }
                    }
                }
                Text("Most registries redact personal data since 2018, so what appears here is only what the source publishes.").font(.caption).foregroundStyle(.tertiary)
            }
        }
    }
}

extension ContactsCard {
    struct Group { var roles: [String]; var contact: RDAPContact }

    /// Contacts with the same name, organisation and phone are one entity
    /// listed under several roles.
    static func merged(_ contacts: [RDAPContact]) -> [Group] {
        var out: [Group] = []
        for c in contacts {
            if let i = out.firstIndex(where: { $0.contact.name == c.name && $0.contact.org == c.org && $0.contact.phone == c.phone && (c.name != nil || c.org != nil) }) {
                out[i].roles.append(contentsOf: c.roles.filter { !out[i].roles.contains($0) })
            } else {
                out.append(Group(roles: c.roles, contact: c))
            }
        }
        return out
    }

    /// A contact whose every published field is a redaction placeholder.
    static func isRedacted(_ c: RDAPContact) -> Bool {
        let fields = [c.name, c.email, c.phone].compactMap { $0 }.filter { !$0.isEmpty }
        return !fields.isEmpty && fields.allSatisfy { $0.uppercased().contains("REDACTED") }
    }
}

struct RegistryDNSSECCard: View {
    var d: RDAPDNSSEC
    var body: some View {
        InfoCard("DNSSEC at the registry", icon: d.signed ? "lock.fill" : "lock.open") {
            if d.signed {
                Text(d.ds.isEmpty ? "The registry reports the delegation as signed." : "DS records held by the registry:").font(.callout)
                ForEach(Array(d.ds.enumerated()), id: \.offset) { _, ds in
                    Text(verbatim: "tag \(ds.keyTag) · alg \(ds.algorithm) · digest \(ds.digestType) · \(ds.digest)").font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                }
            } else {
                Text("No DS record at the registry: the zone is not signed as far as resolvers are concerned, even if it publishes DNSKEYs. Enabling DNSSEC means giving your registrar the DS record.").font(.callout).foregroundStyle(.secondary)
            }
        }
    }
}
