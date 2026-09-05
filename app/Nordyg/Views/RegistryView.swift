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
                        Pill(text: expiryLabel(d), icon: "calendar", color: d < 0 ? .red : d < 30 ? .orange : .green, mono: true, help: "Days until the registration expires, from the \\(result.source.uppercased()) expiration date. Most registrars auto-renew before this date.")
                    }
                    if result.dnssec.known {
                        Pill(text: result.dnssec.signed ? "DS at registry" : "no DS at registry", icon: result.dnssec.signed ? "lock.fill" : "lock.open", color: result.dnssec.signed ? .green : .secondary,
                             help: "Whether the registry holds DS records for this delegation, which is what makes the zone's DNSSEC signatures count. The Query and Trace modes validate the actual chain.")
                    }
                    if result.nsMismatch {
                        Pill(text: "NS mismatch", icon: "exclamationmark.triangle.fill", color: .orange, help: "The nameservers on file at the registry differ from the NS records the zone publishes. The registry's list is what the parent zone delegates to; the zone's own list is what resolvers see afterwards. They should agree.")
                    }
                } else {
                    Pill(text: "not registered", icon: "questionmark.circle", color: .orange, help: "The registry has no record for this name. It may be available, reserved, or under a TLD whose registry only answers for exact registered names.")
                }
                Pill(text: result.server, icon: "server.rack", mono: true, help: "The registry server that answered." + (result.registrarServer.map { "\nRegistrar server followed for contacts: \($0)" } ?? ""))
                Spacer()
                Text(result.domain).font(.system(.callout, design: .monospaced).weight(.semibold))
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
                        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.orange.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius: 8))
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
                        ContentUnavailableView("Not registered", systemImage: "questionmark.circle", description: Text("\(result.domain) has no record at \(result.server)."))
                            .frame(height: 200)
                    }
                    InfoCard("Raw response", icon: "doc.plaintext", startOpen: false) {
                        Text(result.raw).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if !result.notices.isEmpty {
                        Text("Notices: " + result.notices.joined(separator: " · ")).font(.caption).foregroundStyle(.tertiary)
                    }
                    Text("Registry data source: \(result.bootstrapSource) bootstrap").font(.caption).foregroundStyle(.tertiary)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    func expiryLabel(_ d: Int) -> String {
        if d < 0 { return "expired \(-d) d ago" }
        if d < 60 { return "expires in \(d) d" }
        return "expires in \(Int((Double(d) / 30.4).rounded())) mo"
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
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 8))
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
                        if let d = result.expiresInDays { Text("(\(d) days)").foregroundStyle(d < 30 ? Color.orange : Color.secondary) }
                    }
                }
                GridRow { Text("Updated").foregroundStyle(.secondary); Text(pretty(result.updated)).font(.system(.body, design: .monospaced)) }
                ForEach(result.events.filter { !["registration", "expiration", "last changed"].contains($0.action) }, id: \.self) { e in
                    GridRow { Text(e.action.capitalizedFirst).foregroundStyle(.secondary); Text(pretty(e.date)).font(.system(.body, design: .monospaced)) }
                }
            }
        }
    }

    func pretty(_ s: String?) -> String {
        guard let s, !s.isEmpty else { return "—" }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) ?? ISO8601DateFormatter().date(from: s) {
            return d.formatted(date: .long, time: .omitted)
        }
        return s
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
                        Pill(text: s.code, color: color(s.code), mono: true)
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
                VStack(alignment: .leading, spacing: 3) {
                    Text("At the registry").font(.caption).foregroundStyle(.secondary)
                    if result.nameservers.isEmpty { Text("none listed").foregroundStyle(.secondary) }
                    ForEach(result.nameservers, id: \.self) { ns in
                        HStack(spacing: 6) {
                            Image(systemName: result.dnsNameservers.isEmpty || result.dnsNameservers.contains(ns) ? "checkmark.circle" : "exclamationmark.circle").foregroundStyle(result.dnsNameservers.isEmpty || result.dnsNameservers.contains(ns) ? Color.green : Color.orange)
                            Text(ns).font(.system(.callout, design: .monospaced))
                        }
                    }
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text("In the zone (NS records)").font(.caption).foregroundStyle(.secondary)
                    if result.dnsNameservers.isEmpty { Text("no answer").foregroundStyle(.secondary) }
                    ForEach(result.dnsNameservers, id: \.self) { ns in
                        HStack(spacing: 6) {
                            Image(systemName: result.nameservers.isEmpty || result.nameservers.contains(ns) ? "checkmark.circle" : "exclamationmark.circle").foregroundStyle(result.nameservers.isEmpty || result.nameservers.contains(ns) ? Color.green : Color.orange)
                            Text(ns).font(.system(.callout, design: .monospaced))
                        }
                    }
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
                ForEach(Array(contacts.enumerated()), id: \.offset) { _, c in
                    HStack(alignment: .top, spacing: 10) {
                        Pill(text: c.roles.joined(separator: ", "), color: .secondary)
                        VStack(alignment: .leading, spacing: 1) {
                            if let n = c.name, !n.isEmpty { Text(n).fontWeight(.semibold) }
                            if let o = c.org, !o.isEmpty { Text(o) }
                            if let e = c.email, !e.isEmpty { Text(e).font(.system(.callout, design: .monospaced)).textSelection(.enabled) }
                            if let p = c.phone, !p.isEmpty { Text(p).font(.system(.callout, design: .monospaced)).textSelection(.enabled) }
                            if let h = c.handle, !h.isEmpty, c.name == nil && c.org == nil { Text("handle \(h)").foregroundStyle(.secondary) }
                        }
                    }
                }
                Text("Most registries redact personal data since 2018; what appears here is what the source publishes.").font(.caption).foregroundStyle(.tertiary)
            }
        }
    }
}

struct RegistryDNSSECCard: View {
    var d: RDAPDNSSEC
    var body: some View {
        InfoCard("DNSSEC at the registry", icon: d.signed ? "lock.fill" : "lock.open") {
            if d.signed {
                Text(d.ds.isEmpty ? "The registry reports the delegation as signed." : "DS records held by the registry:").font(.callout)
                ForEach(Array(d.ds.enumerated()), id: \.offset) { _, ds in
                    Text("tag \(ds.keyTag) · alg \(ds.algorithm) · digest \(ds.digestType) · \(ds.digest)").font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                }
            } else {
                Text("No DS record at the registry: the zone is not signed as far as resolvers are concerned, even if it publishes DNSKEYs. Enabling DNSSEC means giving your registrar the DS record.").font(.callout).foregroundStyle(.secondary)
            }
        }
    }
}
