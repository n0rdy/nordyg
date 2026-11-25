import SwiftUI

struct TraceView: View {
    @EnvironmentObject var model: AppModel
    var result: TraceResult
    private var tab: Binding<String> {
        Binding(get: { model.resultTabs[.trace] ?? "hops" }, set: { model.resultTabs[.trace] = $0 })
    }

    var total: Double { result.hops.map(\.exchange.rttMs).reduce(0, +) }

    var body: some View {
        VStack(spacing: 0) {
            StatusStrip {
                RcodeBadge(rcode: result.final.rcode)
                if let d = result.dnssec { StatusBadge(status: d.status) }
                Meta(text: plural(result.hops.count, "hop"), help: Glossary.hops)
                Dot()
                Meta(text: ms(total) + " in total", help: Glossary.totalTime)
                Dot()
                Meta(text: plural(result.final.answer.filter { $0.type != "RRSIG" }.count, "answer"), help: Glossary.answers)
            }
            Divider()
            TabRow {
                Picker("", selection: tab) {
                    Text("Path").tag("hops")
                    Text("Final answer").tag("final")
                    Text("DNSSEC").tag("dnssec")
                }
            }
            Divider()
            switch tab.wrappedValue {
            case "final": RecordsView(messages: [result.final])
            case "dnssec": DNSSECView(result: result.dnssec)
            default: TraceTimeline(hops: result.hops)
            }
        }
    }
}

/// Vertical timeline: one node per hop, latency bars, lock markers where a
/// DS record hands trust down.
struct TraceTimeline: View {
    var hops: [TraceHop]
    var maxRTT: Double { max(hops.map(\.exchange.rttMs).max() ?? 1, 1) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(hops.enumerated()), id: \.offset) { i, hop in
                    // A restart from the root after a CNAME answer: say why,
                    // or the second descent looks like a repeat.
                    if i > 0, hop.zone == ".", let target = cnameTarget(hops[i - 1]) {
                        CNAMEFollow(target: target)
                    }
                    HopRow(index: i, hop: hop, isLast: i == hops.count - 1, fraction: hop.exchange.rttMs / maxRTT)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// The last CNAME target in a hop's answer, if the hop ended on a CNAME.
func cnameTarget(_ hop: TraceHop) -> String? {
    guard hop.referral == nil else { return nil }
    return hop.message.answer.last { $0.type == "CNAME" }?.rdata
}

/// The marker between a CNAME answer and the trace that follows it.
struct CNAMEFollow: View {
    var target: String
    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: "arrow.turn.down.right").foregroundStyle(.secondary).frame(width: 26)
            HStack(spacing: 6) {
                Text("follows the CNAME to").foregroundStyle(.secondary)
                Text(prose(target)).font(.system(.callout, design: .monospaced).weight(.semibold)).textSelection(.enabled)
                Text("from the root").foregroundStyle(.secondary)
            }
            .font(.callout)
        }
        .padding(.bottom, 18)
    }
}

struct HopRow: View {
    var index: Int
    var hop: TraceHop
    var isLast: Bool
    var fraction: Double
    @State private var showMessage = false

    /// "198.41.0.4:53" → "198.41.0.4"; other ports stay.
    static func host(_ addr: String) -> String {
        if addr.hasSuffix("]:53") { return String(addr.dropFirst().dropLast(4)) }
        if addr.hasSuffix(":53"), addr.filter({ $0 == ":" }).count == 1 { return String(addr.dropLast(3)) }
        return addr
    }

    static func emptyAnswer(_ hop: TraceHop) -> String {
        let q = hop.message.question.first
        let name = prose(q?.name ?? "")
        let type = q?.type ?? ""
        let zone = hop.zone == "." ? "the root zone" : proseZone(hop.zone)
        // Compact denial (RFC 9824): NOERROR with an NSEC that says NXNAME.
        let compactNX = hop.message.authority.contains { $0.type == "NSEC" && $0.rdata.contains("NXNAME") }
        if hop.message.rcode == "NXDOMAIN" || compactNX {
            return "No such name: \(zone) says \(name) does not exist."
        }
        if hop.message.rcode == "NOERROR" {
            return "No \(type) record: \(name) exists, but \(zone) has no \(type) record for it."
        }
        return "No answer (\(hop.message.rcode))."
    }

    var nodeColor: Color {
        if hop.referral != nil { return .accentColor }
        return Rcode.color(hop.message.rcode)
    }

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            // Rail
            VStack(spacing: 0) {
                ZStack {
                    Circle().fill(nodeColor).frame(width: 26, height: 26)
                    Text(verbatim: "\(index + 1)").font(.caption.weight(.bold)).foregroundStyle(.white)
                }
                if !isLast {
                    Rectangle().fill(Color.secondary.opacity(0.3)).frame(width: 2).frame(maxHeight: .infinity)
                }
            }
            .frame(width: 26)

            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text(hop.zone == "." ? "root" : prose(hop.zone)).font(.system(.title3, design: .monospaced).weight(.semibold))
                    if hop.message.flags.aa {
                        Pill(
                            text: "authoritative", icon: "checkmark.seal.fill", color: .green,
                            help: "AA flag set: this server is authoritative for the zone and answered from its own data, not a cache.")
                    }
                    if hop.referral != nil {
                        Pill(
                            text: "referral", icon: "arrow.turn.down.right", color: .accentColor,
                            help: "This server does not hold the answer. It pointed to the nameservers of the next zone down.")
                    }
                    if hop.referral == nil && hop.message.rcode != "NOERROR" { RcodeBadge(rcode: hop.message.rcode) }
                    Spacer()
                }
                Text(verbatim: "asked \(prose(hop.server.name)) at \(Self.host(hop.server.address))")
                    .font(.callout).foregroundStyle(.secondary)

                // Latency bar
                HStack(spacing: 8) {
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            RoundedRectangle(cornerRadius: 3).fill(Color.secondary.opacity(0.12))
                            RoundedRectangle(cornerRadius: 3).fill(nodeColor.opacity(0.7))
                                .frame(width: max(4, geo.size.width * fraction))
                        }
                    }
                    .frame(height: 8)
                    Text(ms(hop.exchange.rttMs)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).frame(
                        width: 60, alignment: .trailing)
                }

                if let ref = hop.referral {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Image(systemName: ref.ds.isEmpty ? "lock.open" : "lock.fill").foregroundStyle(
                                ref.ds.isEmpty ? Color.secondary : Color.yellow)
                            Text(
                                verbatim: ref.ds.isEmpty
                                    ? "hands off \(prose(ref.zone)) without a DS record (unsigned below here)"
                                    : "hands off \(prose(ref.zone)) with \(plural(ref.ds.count, "DS record"))"
                            )
                            .font(.callout)
                        }
                        Text(ref.nameservers.joined(separator: "  ")).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        if !ref.glue.isEmpty {
                            Text(
                                "glue: "
                                    + ref.glue.keys.sorted().map { "\($0) → \(ref.glue[$0]!.joined(separator: ", "))" }.joined(
                                        separator: "   ")
                            )
                            .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
                        }
                    }
                    .inset()
                } else if hop.message.answer.isEmpty {
                    // An empty answer still says something: name or type absent.
                    Text(Self.emptyAnswer(hop))
                        .font(.callout)
                        .inset(fullWidth: true)
                } else {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(hop.message.answer.enumerated()), id: \.offset) { _, r in
                            HStack(spacing: 8) {
                                TypeBadge(type: r.type)
                                Text(r.rdata).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                    }
                    .inset()
                }

                // The message link sits inline with the facts it belongs to. At
                // the far right edge it is easy to miss.
                HStack(spacing: 6) {
                    Text(verbatim: "picked from \(plural(hop.candidates.count, "address", "addresses")) · \(hop.message.sizeBytes) bytes")
                        .foregroundStyle(.tertiary)
                        .help("The server addresses the previous hop pointed to. Nordyg asked the first that answered.")
                    Dot()
                    Button(showMessage ? "hide the full message" : "show the full message") { showMessage.toggle() }.buttonStyle(.link)
                }
                .font(.caption)
                if showMessage {
                    Text(hop.message.text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .inset(fill: Color.secondary.opacity(0.08), fullWidth: true)
                }
            }
            .padding(.bottom, isLast ? 0 : 18)
        }
    }
}
