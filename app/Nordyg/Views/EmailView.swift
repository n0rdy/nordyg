import SwiftUI

/// The email deliverability report: one card per check, each with a verdict.
struct EmailView: View {
    var result: EmailResult

    var body: some View {
        VStack(spacing: 0) {
            StatusStrip {
                VerdictPill(verdict: result.overall)
                Text(result.overall.message).font(.callout)
                Spacer()
                Text(prose(result.domain)).font(.system(.callout, design: .monospaced).weight(.semibold))
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    MXCard(section: result.mx)
                    SPFCard(section: result.spf)
                    DKIMCard(section: result.dkim)
                    DMARCCard(section: result.dmarc)
                    MTASTSCard(section: result.mtaSts)
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
    @ViewBuilder var details: Content
    @State private var open: Bool

    init(_ title: String, subtitle: String, verdict: Verdict, startOpen: Bool = false, @ViewBuilder details: () -> Content) {
        self.title = title
        self.subtitle = subtitle
        self.verdict = verdict
        self.details = details()
        _open = State(initialValue: startOpen || verdict.status == "fail" || verdict.status == "warn")
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
                Button(open ? "Hide" : "Details") { open.toggle() }.buttonStyle(.link).font(.callout)
            }
            if open {
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
        CheckCard("Mail servers", subtitle: "MX", verdict: section.verdict, startOpen: true) {
            if section.nullMx {
                Text("MX 0 .  (null MX)")
            }
            ForEach(Array(section.hosts.enumerated()), id: \.offset) { _, h in
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text("\(h.preference)").foregroundStyle(.secondary).frame(width: 28, alignment: .trailing)
                        Text(prose(h.exchange)).fontWeight(.semibold)
                        Text(h.addresses.joined(separator: "  ")).foregroundStyle(.secondary)
                        if let e = h.error { Text(e).foregroundStyle(.red) }
                    }
                    ForEach(Array(h.ptr.enumerated()), id: \.offset) { _, p in
                        HStack(spacing: 6) {
                            Image(systemName: p.matches ? "arrow.uturn.left.circle.fill" : "arrow.uturn.left.circle").foregroundStyle(p.matches ? Color.green : Color.orange)
                            Text("\(p.ip) → \(p.names.isEmpty ? "no PTR" : p.names.map(prose).joined(separator: ", "))")
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
        CheckCard("Sender policy", subtitle: "SPF", verdict: section.verdict) {
            ForEach(section.records, id: \.self) { r in Text(r).textSelection(.enabled) }
            if section.decoded != nil || !section.includes.isEmpty {
                HStack(spacing: 8) {
                    Text("DNS lookups").foregroundStyle(.secondary)
                    LookupMeter(used: section.totalLookups)
                    Text("\(section.totalLookups) / 10")
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
                                Text("\(inc.lookups) lookup\(inc.lookups == 1 ? "" : "s")").foregroundStyle(.secondary)
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
    var section: DKIMSection
    var body: some View {
        let found = section.selectors.filter(\.found)
        let missing = section.selectors.filter { !$0.found }
        CheckCard("Signing keys", subtitle: "DKIM", verdict: section.verdict) {
            ForEach(Array(found.enumerated()), id: \.offset) { _, s in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(s.selector).fontWeight(.semibold)
                        if let bits = s.decoded?["key_bits"], let kt = s.decoded?["key_type"] { Text("\(bits.display)-bit \(kt.display)").foregroundStyle(.secondary) }
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
    }
}

struct DMARCCard: View {
    var section: DMARCSection
    var body: some View {
        CheckCard("Policy", subtitle: "DMARC", verdict: section.verdict) {
            Text(prose(section.name)).foregroundStyle(.tertiary)
            ForEach(section.records, id: \.self) { r in Text(r).textSelection(.enabled) }
            if let tags = section.decoded?["tags"]?.objectValue {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 2) {
                    ForEach(["p", "sp", "pct", "rua", "ruf", "adkim", "aspf"], id: \.self) { k in
                        if let v = tags[k], v != .null {
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

struct MTASTSCard: View {
    var section: MTASTSSection
    var body: some View {
        CheckCard("Transport security", subtitle: "MTA-STS", verdict: section.verdict) {
            if let r = section.record { Text(r).textSelection(.enabled) }
            if let u = section.policyUrl { Text(u).foregroundStyle(.secondary) }
            if let t = section.policyText {
                Text(t.trimmingCharacters(in: .whitespacesAndNewlines))
                    .padding(6).background(Color.secondary.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius: 4))
                    .textSelection(.enabled)
            }
            if let e = section.error { Text(e).foregroundStyle(.red) }
        }
    }
}

struct BIMICard: View {
    var section: BIMISection
    var body: some View {
        CheckCard("Brand logo", subtitle: "BIMI", verdict: section.verdict) {
            if let r = section.record { Text(r).textSelection(.enabled) }
            if let l = section.logo, let url = URL(string: l) { Link(l, destination: url) }
            if let a = section.evidence, let url = URL(string: a) { Link(a, destination: url) }
        }
    }
}

struct DNSBLCard: View {
    var section: DNSBLSection
    var body: some View {
        CheckCard("Blocklists", subtitle: "DNSBL", verdict: section.verdict) {
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
