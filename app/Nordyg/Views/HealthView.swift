import SwiftUI

/// The domain health report: is the zone correctly delegated and served?
/// One card per check, the same chrome as the email report.
struct HealthView: View {
    var result: HealthResult

    var body: some View {
        VStack(spacing: 0) {
            StatusStrip {
                VerdictPill(verdict: result.overall)
                Text(result.overall.message).font(.callout)
                Spacer()
                Text(prose(result.zone)).font(.system(.callout, design: .monospaced).weight(.semibold))
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    DelegationCard(d: result.delegation)
                    ZoneServersCard(section: result.nameservers)
                    SOACard(section: result.soa)
                    GlueCard(section: result.glue)
                    ZoneDNSSECCard(section: result.dnssec)
                    CAACard(section: result.caa)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

/// Findings under a card, each with its own severity icon.
struct FindingList: View {
    var findings: [Verdict]
    var body: some View {
        let shown = findings.filter { $0.status != "ok" }
        if !shown.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                ForEach(Array(shown.enumerated()), id: \.offset) { _, f in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Image(systemName: VerdictStyle.icon(f.status)).foregroundStyle(VerdictStyle.color(f.status))
                        Text(f.message).textSelection(.enabled)
                    }
                }
            }
            .font(.callout)
            .padding(.top, 2)
        }
    }
}

struct DelegationCard: View {
    var d: HealthDelegation
    var body: some View {
        CheckCard("Delegation", subtitle: d.parent.isEmpty ? "NS" : "NS at \(proseZone(d.parent)) vs the zone", verdict: d.verdict) {
            let names = Array(Set(d.parentNs + d.childNs)).sorted()
            if !names.isEmpty {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 3) {
                    GridRow {
                        Text("nameserver").foregroundStyle(.secondary)
                        Text("parent").foregroundStyle(.secondary)
                        Text("zone").foregroundStyle(.secondary)
                    }
                    ForEach(names, id: \.self) { n in
                        GridRow {
                            Text(prose(n)).fontWeight(.semibold)
                            Presence(on: d.parentNs.contains(n))
                            Presence(on: d.childNs.contains(n))
                        }
                    }
                }
            }
            FindingList(findings: d.findings)
        }
    }
}

struct Presence: View {
    var on: Bool
    var body: some View {
        Image(systemName: on ? "checkmark" : "minus").foregroundStyle(on ? Color.green : Color.orange)
    }
}

struct ZoneServersCard: View {
    var section: HealthNameservers
    var body: some View {
        CheckCard("Nameservers", subtitle: "every address, asked directly", verdict: section.verdict, startOpen: true) {
            ScrollView(.horizontal, showsIndicators: false) {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                    GridRow {
                        ForEach(["", "nameserver", "address", "serial", "UDP", "TCP", "EDNS", "AXFR", "recursion", "time"], id: \.self) { h in
                            Text(h).foregroundStyle(.secondary)
                        }
                    }
                    ForEach(Array(section.servers.enumerated()), id: \.offset) { _, s in
                        GridRow {
                            Image(systemName: VerdictStyle.icon(s.status)).foregroundStyle(VerdictStyle.color(s.status))
                            Text(prose(s.name)).fontWeight(.semibold)
                            Text(s.ip.isEmpty ? "no address" : s.ip).foregroundStyle(s.ip.isEmpty ? Color.red : Color.primary)
                            Text(s.serial.map(String.init) ?? "–")
                            if s.skipped {
                                Text("not checked: no IPv6 route on this Mac").foregroundStyle(.secondary).gridCellColumns(6)
                            } else {
                                Check(ok: s.answered && s.authoritative, label: s.answered ? (s.authoritative ? "AA" : (s.rcode ?? "?")) : "no answer")
                                Check(ok: s.tcp, label: s.tcp ? "yes" : "no")
                                Check(ok: s.edns, label: s.edns ? "yes" : "no", warnOnly: true)
                                Check(ok: s.axfr != "allowed", label: axfrLabel(s.axfr), warnOnly: true)
                                Check(ok: !s.recursion, label: s.recursion ? "open" : "closed", warnOnly: true)
                                Text(s.answered ? ms(s.rttMs) : "–").foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            FindingList(findings: section.findings)
        }
    }

    func axfrLabel(_ s: String) -> String {
        switch s {
        case "allowed": return "open"
        case "refused": return "refused"
        case "no_answer": return "no answer"
        default: return "–"
        }
    }
}

/// A cell that is green when fine, orange or red when not.
struct Check: View {
    var ok: Bool
    var label: String
    var warnOnly = false
    var body: some View {
        Text(label).foregroundStyle(ok ? Color.secondary : (warnOnly ? Color.orange : Color.red))
    }
}

struct SOACard: View {
    var section: HealthSOA
    var body: some View {
        CheckCard("Start of authority", subtitle: "SOA", verdict: section.verdict) {
            if let r = section.record {
                Text(r.rdata).textSelection(.enabled)
                if let f = r.fields {
                    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 2) {
                        ForEach(["refresh", "retry", "expire", "minimum"], id: \.self) { k in
                            if let v = f[k] {
                                GridRow {
                                    Text(k).foregroundStyle(.secondary).help(SOAGlossary.text(k))
                                    Text(SOAGlossary.duration(v.display))
                                }
                            }
                        }
                    }
                    .padding(.top, 2)
                }
            }
            if section.serials.count > 1 {
                ForEach(section.serials, id: \.serial) { g in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(String(g.serial)).fontWeight(.semibold)
                        Text(g.servers.joined(separator: ", ")).foregroundStyle(.secondary)
                    }
                }
            }
            FindingList(findings: section.findings)
        }
    }
}

enum SOAGlossary {
    static func text(_ k: String) -> String {
        switch k {
        case "refresh": return "How often secondaries check the primary for a newer serial."
        case "retry": return "How soon a secondary tries again after a failed refresh."
        case "expire": return "How long a secondary keeps serving the zone without reaching the primary."
        case "minimum": return "How long resolvers cache a \"no such name\" answer (RFC 2308)."
        default: return ""
        }
    }
    static func duration(_ raw: String) -> String {
        guard let s = Int(raw) else { return raw }
        let human: String
        switch s {
        case let s where s >= 86400 && s % 86400 == 0: human = "\(s / 86400) d"
        case let s where s >= 3600 && s % 3600 == 0: human = "\(s / 3600) h"
        case let s where s >= 60 && s % 60 == 0: human = "\(s / 60) min"
        default: return "\(s) s"
        }
        return "\(human)  (\(s) s)"
    }
}

struct GlueCard: View {
    var section: HealthGlue
    var body: some View {
        CheckCard("Glue", subtitle: "addresses the parent hands out", verdict: section.verdict) {
            let inside = section.entries.filter(\.inBailiwick)
            if inside.isEmpty {
                Text("Every nameserver is outside the zone, so resolvers look its address up separately.").foregroundStyle(.secondary).font(.callout)
            } else {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 3) {
                    GridRow {
                        Text("")
                        Text("nameserver").foregroundStyle(.secondary)
                        Text("parent's glue").foregroundStyle(.secondary)
                        Text("zone's own records").foregroundStyle(.secondary)
                    }
                    ForEach(inside, id: \.name) { e in
                        GridRow {
                            Image(systemName: e.match ? "checkmark.circle.fill" : "xmark.circle.fill").foregroundStyle(e.match ? Color.green : Color.red)
                            Text(prose(e.name)).fontWeight(.semibold)
                            Text(e.parent.isEmpty ? "none" : e.parent.joined(separator: "  ")).foregroundStyle(e.parent.isEmpty ? Color.red : Color.primary)
                            Text(e.child.isEmpty ? "none" : e.child.joined(separator: "  "))
                        }
                    }
                }
            }
            FindingList(findings: section.findings)
        }
    }
}

struct ZoneDNSSECCard: View {
    var section: HealthDNSSEC
    var body: some View {
        CheckCard("Signing", subtitle: "DNSSEC", verdict: section.verdict) {
            if !section.status.isEmpty {
                HStack(spacing: 8) {
                    StatusBadge(status: section.status)
                    if let r = section.result, !r.reason.isEmpty { Text(r.reason).foregroundStyle(.secondary).textSelection(.enabled) }
                }
            }
            ForEach(Array(section.ds.enumerated()), id: \.offset) { _, d in
                HStack(spacing: 8) {
                    TypeBadge(type: "DS")
                    Text(d.rdata).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                }
            }
            if let r = section.result, !r.chain.isEmpty {
                ChainSection(chain: r.chain)
                    .font(.body)
                    .padding(.top, 4)
            }
            FindingList(findings: section.findings)
        }
    }
}

struct CAACard: View {
    var section: HealthCAA
    var body: some View {
        CheckCard("Certificate authorities", subtitle: "CAA", verdict: section.verdict) {
            if let at = section.foundAt { Text("found at \(prose(at))").foregroundStyle(.secondary) }
            ForEach(Array(section.records.enumerated()), id: \.offset) { _, c in
                HStack(spacing: 8) {
                    Text(c.tag).fontWeight(.semibold).frame(minWidth: 70, alignment: .leading)
                    Text(c.value).textSelection(.enabled)
                    if c.flags & 128 != 0 { Pill(text: "critical", color: .orange) }
                }
            }
            FindingList(findings: section.findings)
        }
    }
}

/// The pasteable report: Markdown with every verdict and finding.
enum HealthReport {
    static func markdown(_ r: HealthResult) -> String {
        var s = "# DNS health of \(prose(r.zone))\n\n"
        s += "**\(VerdictStyle.label(r.overall.status)):** \(r.overall.message)\n\n"
        let sections: [(String, Verdict, [Verdict])] = [
            ("Delegation", r.delegation.verdict, r.delegation.findings),
            ("Nameservers", r.nameservers.verdict, r.nameservers.findings),
            ("SOA", r.soa.verdict, r.soa.findings),
            ("Glue", r.glue.verdict, r.glue.findings),
            ("DNSSEC", r.dnssec.verdict, r.dnssec.findings),
            ("CAA", r.caa.verdict, r.caa.findings),
        ]
        for (title, v, findings) in sections {
            s += "## \(title): \(VerdictStyle.label(v.status))\n\n\(v.message)\n\n"
            for f in findings where f.status != "ok" && f.message != v.message {
                s += "- \(VerdictStyle.label(f.status)): \(f.message)\n"
            }
            if findings.contains(where: { $0.status != "ok" && $0.message != v.message }) { s += "\n" }
            if title == "Nameservers", !r.nameservers.servers.isEmpty {
                s += "| Nameserver | Address | Serial | Answer | TCP | EDNS | AXFR | Recursion |\n|---|---|---:|---|---|---|---|---|\n"
                for sv in r.nameservers.servers {
                    if sv.skipped {
                        s += "| \(prose(sv.name)) | \(sv.ip) | | not checked (no IPv6 route) | | | | |\n"
                        continue
                    }
                    let answer = sv.answered ? (sv.authoritative ? "authoritative" : (sv.rcode ?? "?")) : "none"
                    s += "| \(prose(sv.name)) | \(sv.ip.isEmpty ? "no address" : sv.ip) | \(sv.serial.map(String.init) ?? "") | \(answer) | \(sv.tcp ? "yes" : "no") | \(sv.edns ? "yes" : "no") | \(sv.axfr) | \(sv.recursion ? "open" : "closed") |\n"
                }
                s += "\n"
            }
        }
        s += "_Checked with Nordyg from the root servers down, asking every nameserver directly._\n"
        return s
    }
}
