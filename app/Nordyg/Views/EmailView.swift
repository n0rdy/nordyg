import SwiftUI

/// The email deliverability report: one card per check, each with a verdict.
struct EmailView: View {
    var result: EmailResult

    var body: some View {
        VStack(spacing: 0) {
            StatusStrip {
                VerdictPill(verdict: result.overall)
                Text(verbatim: "\(prose(result.domain)): \(result.overall.message)").font(.callout)
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    MXCard(section: result.mx)
                    SPFCard(section: result.spf)
                    DKIMCard(section: result.dkim)
                    DMARCCard(section: result.dmarc)
                    TransportCard(sts: result.mtaSts, dane: result.dane, verdict: result.transport)
                    BIMICard(section: result.bimi)
                    DNSBLCard(section: result.dnsbl)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

/// Shared card chrome: title, verdict, one-line message, expandable details.
struct CheckCard<Content: View>: View {
    var title: String
    var subtitle: String
    var verdict: Verdict
    var startOpen: Bool = false
    /// False when there is nothing behind the verdict: no Details button
    /// that opens onto an empty box.
    var hasDetails: Bool = true
    @ViewBuilder var details: Content
    @State private var open: Bool

    init(_ title: String, subtitle: String, verdict: Verdict, startOpen: Bool = false, hasDetails: Bool = true, @ViewBuilder details: () -> Content) {
        self.title = title
        self.subtitle = subtitle
        self.verdict = verdict
        self.hasDetails = hasDetails
        self.details = details()
        var initial = hasDetails && (startOpen || verdict.status == "fail" || verdict.status == "warn")
        #if DEBUG
        if let o = DebugHooks.openCards { initial = hasDetails && (o == "open" || o == title) }
        #endif
        _open = State(initialValue: initial)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: VerdictStyle.icon(verdict.status)).foregroundStyle(VerdictStyle.color(verdict.status)).font(.title3)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(title).font(.headline)
                        Text(subtitle).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    Text(verdict.message).font(.callout).textSelection(.enabled)
                }
                Spacer()
                if hasDetails {
                    Button(open ? "Hide" : "Details") { open.toggle() }.buttonStyle(.link).font(.callout)
                }
            }
            if open && hasDetails {
                Divider()
                details
                    .font(.system(.callout, design: .monospaced))
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VerdictStyle.color(verdict.status).opacity(0.06))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(VerdictStyle.color(verdict.status).opacity(0.25)))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct MXCard: View {
    var section: MXSection
    var body: some View {
        CheckCard("Mail servers", subtitle: "MX", verdict: section.verdict, startOpen: true, hasDetails: !section.hosts.isEmpty || section.nullMx) {
            if section.nullMx {
                Text("MX 0 .  (null MX)")
            }
            ForEach(Array(section.hosts.filter { !section.nullMx || $0.exchange != "." }.enumerated()), id: \.offset) { _, h in
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(verbatim: "\(h.preference)").foregroundStyle(.secondary).frame(width: 28, alignment: .trailing)
                        Text(prose(h.exchange)).fontWeight(.semibold)
                        Text(h.addresses.joined(separator: "  ")).foregroundStyle(.secondary)
                        if let e = h.error { Text(e).foregroundStyle(.red) }
                    }
                    ForEach(Array(h.ptr.enumerated()), id: \.offset) { _, p in
                        HStack(spacing: 6) {
                            Image(systemName: p.matches ? "arrow.uturn.left.circle.fill" : "arrow.uturn.left.circle").foregroundStyle(p.matches ? Color.green : Color.orange)
                            Text(verbatim: "\(p.ip) → \(p.names.isEmpty ? "no PTR" : p.names.map(prose).joined(separator: ", "))")
                            Text(p.matches ? "forward-confirmed" : "does not point back").foregroundStyle(p.matches ? Color.secondary : Color.orange)
                            if let e = p.error { Text(e).foregroundStyle(.red) }
                        }
                        .padding(.leading, 36)
                        .font(.system(.caption, design: .monospaced))
                    }
                }
            }
        }
    }
}

struct SPFCard: View {
    var section: SPFSection
    var body: some View {
        CheckCard("Sender policy", subtitle: "SPF", verdict: section.verdict, hasDetails: !section.records.isEmpty) {
            ForEach(section.records, id: \.self) { r in Text(r).textSelection(.enabled) }
            if section.decoded != nil || !section.includes.isEmpty {
                HStack(spacing: 8) {
                    Text("DNS lookups").foregroundStyle(.secondary)
                    LookupMeter(used: section.totalLookups)
                    Text(verbatim: "\(section.totalLookups) / 10")
                }
                .padding(.top, 4)
            }
            if !section.includes.isEmpty {
                Text("Include chain").foregroundStyle(.secondary).padding(.top, 4)
                ForEach(Array(section.includes.enumerated()), id: \.offset) { _, inc in
                    HStack(alignment: .top, spacing: 6) {
                        Text(String(repeating: "    ", count: inc.depth - 1) + "↳").foregroundStyle(.tertiary)
                        VStack(alignment: .leading, spacing: 1) {
                            HStack(spacing: 8) {
                                Text(prose(inc.name)).fontWeight(.semibold)
                                Text(verbatim: "\(inc.lookups) lookup\(inc.lookups == 1 ? "" : "s")").foregroundStyle(.secondary)
                                if let e = inc.error { Text(e).foregroundStyle(.red) }
                            }
                            if let r = inc.record { Text(r).foregroundStyle(.secondary).textSelection(.enabled) }
                        }
                    }
                }
            }
            if let problems = section.decoded?["problems"]?.arrayValue, !problems.isEmpty {
                ProblemList(problems: problems)
            }
        }
    }
}

struct LookupMeter: View {
    var used: Int
    var body: some View {
        HStack(spacing: 2) {
            ForEach(0..<10, id: \.self) { i in
                RoundedRectangle(cornerRadius: 2)
                    .fill(i < used ? (used > 10 ? Color.red : used > 8 ? Color.orange : Color.green) : Color.secondary.opacity(0.15))
                    .frame(width: 10, height: 10)
            }
        }
    }
}

struct DKIMCard: View {
    @EnvironmentObject var model: AppModel
    var section: DKIMSection
    var body: some View {
        let found = section.selectors.filter(\.found)
        let missing = section.selectors.filter { !$0.found }
        CheckCard("Signing keys", subtitle: "DKIM", verdict: section.verdict) {
            if section.wildcard == true, let first = found.first {
                // One wildcard answer, not the same revoked key 60 times.
                Text(verbatim: "Every selector tried (\(found.count)) returns the same record:").foregroundStyle(.secondary)
                Text(first.record ?? "").textSelection(.enabled)
            } else {
            ForEach(Array(found.enumerated()), id: \.offset) { _, s in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(s.selector).fontWeight(.semibold)
                        if let bits = s.decoded?["key_bits"], bits.display != "0", let kt = s.decoded?["key_type"] { Text(verbatim: "\(bits.display)-bit \(kt.display)").foregroundStyle(.secondary) }
                        if s.decoded?["revoked"] == .bool(true) { Text("revoked").foregroundStyle(.red) }
                        Text(prose(s.name)).foregroundStyle(.tertiary)
                    }
                    if let problems = s.decoded?["problems"]?.arrayValue, !problems.isEmpty { ProblemList(problems: problems) }
                }
            }
            if !missing.isEmpty {
                Text("Not found at: " + missing.map(\.selector).joined(separator: ", ")).foregroundStyle(.tertiary).font(.system(.caption, design: .monospaced))
            }
            }
            // Providers with random or dated selectors cannot be guessed;
            // the selector is the s= tag of a DKIM-Signature header.
            HStack(spacing: 8) {
                Text("Your selector").foregroundStyle(.secondary)
                TextField("from the s= tag of a DKIM-Signature header", text: $model.dkimSelector)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                    .onSubmit { model.run() }
                Button("Check again") { model.run() }
                    .disabled(model.dkimSelector.trimmingCharacters(in: .whitespaces).isEmpty || !model.canRun)
            }
            .padding(.top, 4)
        }
    }
}

struct DMARCCard: View {
    var section: DMARCSection
    var body: some View {
        CheckCard("Policy", subtitle: "DMARC", verdict: section.verdict, hasDetails: !section.records.isEmpty) {
            Text(prose(section.name)).foregroundStyle(.tertiary)
            ForEach(section.records, id: \.self) { r in Text(r).textSelection(.enabled) }
            if let tags = section.decoded?["tags"]?.objectValue {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 2) {
                    ForEach(["p", "sp", "pct", "rua", "ruf", "adkim", "aspf"], id: \.self) { k in
                        if let v = tags[k], v != .null, !v.display.isEmpty, v.display != "[]" {
                            GridRow {
                                Text(k).foregroundStyle(.secondary)
                                Text(v.display)
                            }
                        }
                    }
                }
                .padding(.top, 4)
            }
            if let problems = section.decoded?["problems"]?.arrayValue, !problems.isEmpty { ProblemList(problems: problems) }
        }
    }
}

/// MTA-STS and DANE: the two ways a domain makes senders require TLS.
struct TransportCard: View {
    var sts: MTASTSSection
    var dane: DANESection
    var verdict: Verdict

    var stsDetails: Bool { sts.record != nil || sts.policyUrl != nil || sts.policyText != nil || sts.error != nil }
    var daneHosts: [DANEHost] { dane.hosts.filter { !$0.tlsa.isEmpty || $0.error != nil } }

    var body: some View {
        CheckCard("Transport security", subtitle: "MTA-STS and DANE", verdict: verdict, hasDetails: stsDetails || !daneHosts.isEmpty) {
            if stsDetails {
                Part(title: "MTA-STS", verdict: sts.verdict, shown: verdict != sts.verdict)
                if let r = sts.record { Text(r).textSelection(.enabled) }
                if let u = sts.policyUrl { Text(u).foregroundStyle(.secondary) }
                if let t = sts.policyText {
                    Text(t.trimmingCharacters(in: .whitespacesAndNewlines))
                        .padding(6).background(Color.secondary.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius: 4))
                        .textSelection(.enabled)
                }
                if let e = sts.error { Text(e).foregroundStyle(.red) }
            }
            if !daneHosts.isEmpty {
                Part(title: "DANE", verdict: dane.verdict, shown: verdict != dane.verdict)
                    .padding(.top, stsDetails ? 6 : 0)
                // Hosts usually share one set of records: list it once per set.
                ForEach(Self.groups(daneHosts), id: \.self) { g in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 8) {
                            Text(g.map { prose($0.exchange) }.joined(separator: ", ")).fontWeight(.semibold)
                            if g[0].error != nil {
                                Text("TLSA lookup failed").font(.callout).foregroundStyle(.orange)
                            } else {
                                Text(g[0].status == "secure" ? "signed" : "not signed").font(.callout)
                                    .foregroundStyle(g[0].status == "secure" ? Color.secondary : Color.orange)
                            }
                        }
                        ForEach(g[0].tlsa, id: \.self) { Text(verbatim: "TLSA \($0)").textSelection(.enabled) }
                        // When port 25 was blocked for every server the verdict
                        // already says so, so rows would only repeat it.
                        if reachedAny {
                            ForEach(g.flatMap { h in h.servers.filter { $0.skipped != true }.map { (h.exchange, $0) } }, id: \.1.ip) { host, s in
                                HStack(spacing: 8) {
                                    Text(s.ip).textSelection(.enabled)
                                    if g.count > 1 { Text(prose(host)).foregroundStyle(.secondary) }
                                    Text(Self.label(s)).font(.callout).foregroundStyle(s.checked && !s.match ? Color.red : Color.secondary)
                                }
                            }
                        }
                    }
                }
                FindingList(findings: dane.findings, verdict: verdict)
            }
        }
    }

    var reachedAny: Bool { dane.hosts.contains { $0.servers.contains(where: \.checked) } }

    /// Hosts with the same records and status, in MX order.
    static func groups(_ hosts: [DANEHost]) -> [[DANEHost]] {
        var out: [[DANEHost]] = []
        for h in hosts {
            if let i = out.firstIndex(where: { Set($0[0].tlsa) == Set(h.tlsa) && $0[0].status == h.status && $0[0].error == h.error }) {
                out[i].append(h)
            } else {
                out.append([h])
            }
        }
        return out
    }

    static func label(_ s: DANEServer) -> String {
        if !s.checked { return "port 25 not reachable from this network" }
        if let e = s.error { return e }
        return s.match ? "certificate matches" : "certificate matches no TLSA record"
    }

    /// A sub-heading with that part's own verdict, when it is not the card's.
    struct Part: View {
        var title: String
        var verdict: Verdict
        var shown: Bool
        var body: some View {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).fontWeight(.semibold)
                if shown {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Image(systemName: VerdictStyle.icon(verdict.status)).foregroundStyle(VerdictStyle.color(verdict.status))
                        Text(verdict.message)
                    }
                    .font(.callout)
                }
            }
        }
    }
}

struct BIMICard: View {
    var section: BIMISection
    var body: some View {
        CheckCard("Brand logo", subtitle: "BIMI", verdict: section.verdict, hasDetails: section.record != nil) {
            if let r = section.record { Text(r).textSelection(.enabled) }
            if let l = section.logo, let url = URL(string: l) { Link(l, destination: url) }
            if let a = section.evidence, let url = URL(string: a) { Link(a, destination: url) }
        }
    }
}

struct DNSBLCard: View {
    var section: DNSBLSection
    var body: some View {
        CheckCard("Blocklists", subtitle: "DNSBL", verdict: section.verdict, hasDetails: !section.checks.isEmpty) {
            let ips = Array(Set(section.checks.map(\.ip))).sorted()
            let zones = Array(Set(section.checks.map(\.zone))).sorted()
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                GridRow {
                    Text("").frame(width: 120)
                    ForEach(zones, id: \.self) { z in Text(z).foregroundStyle(.secondary).font(.system(.caption, design: .monospaced)) }
                }
                ForEach(ips, id: \.self) { ip in
                    GridRow {
                        Text(ip)
                        ForEach(zones, id: \.self) { z in
                            let c = section.checks.first { $0.ip == ip && $0.zone == z }
                            HStack(spacing: 4) {
                                if c?.listed == true {
                                    Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                                    Text(c?.response ?? "listed")
                                } else if c?.blocked == true {
                                    Image(systemName: "minus.circle").foregroundStyle(.secondary)
                                    Text("refused").foregroundStyle(.secondary)
                                } else if let e = c?.error {
                                    Image(systemName: "questionmark.circle").foregroundStyle(.orange)
                                    Text(e).foregroundStyle(.orange).lineLimit(1)
                                } else {
                                    Image(systemName: "checkmark.circle").foregroundStyle(.green)
                                    Text("clean").foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

struct ProblemList: View {
    var problems: [JSONValue]
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(problems.enumerated()), id: \.offset) { _, p in
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: severityIcon(p["severity"]?.stringValue ?? "info")).foregroundStyle(severityColor(p["severity"]?.stringValue ?? "info"))
                    Text(p["message"]?.display ?? "").textSelection(.enabled)
                }
                .font(.callout)
            }
        }
        .padding(.top, 4)
    }
}
