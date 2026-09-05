import SwiftUI

struct TraceView: View {
    @EnvironmentObject var model: AppModel
    var result: TraceResult
    @State private var tab = "hops"

    var total: Double { result.hops.map(\.exchange.rttMs).reduce(0, +) }

    var body: some View {
        VStack(spacing: 0) {
            StatusStrip {
                RcodeBadge(rcode: result.final.rcode)
                if let d = result.dnssec { StatusBadge(status: d.status) }
                Pill(text: "\(result.hops.count) hops", icon: "point.3.connected.trianglepath.dotted", color: .accentColor, mono: true, help: Glossary.hops)
                Pill(text: ms(total) + " total", icon: "timer", mono: true, help: Glossary.totalTime)
                Pill(text: "\(result.final.answer.count) answers", mono: true, help: Glossary.answers)
                Spacer()
                Picker("", selection: $tab) {
                    Text("Path").tag("hops")
                    Text("Final answer").tag("final")
                    Text("DNSSEC").tag("dnssec")
                }
                .pickerStyle(.segmented).frame(width: 280)
            }
            Divider()
            switch tab {
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
                    HopRow(index: i, hop: hop, isLast: i == hops.count - 1, fraction: hop.exchange.rttMs / maxRTT)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct HopRow: View {
    var index: Int
    var hop: TraceHop
    var isLast: Bool
    var fraction: Double
    @State private var showMessage = false

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
                    Text("\(index + 1)").font(.caption.weight(.bold)).foregroundStyle(.white)
                }
                if !isLast {
                    Rectangle().fill(Color.secondary.opacity(0.3)).frame(width: 2).frame(maxHeight: .infinity)
                }
            }
            .frame(width: 26)

            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text(hop.zone == "." ? "root" : prose(hop.zone)).font(.system(.title3, design: .monospaced).weight(.semibold))
                    if hop.message.flags.aa { Pill(text: "authoritative", icon: "checkmark.seal.fill", color: .green, help: "AA flag set: this server is authoritative for the zone and answered from its own data, not a cache.") }
                    if hop.referral != nil { Pill(text: "referral", icon: "arrow.turn.down.right", color: .accentColor, help: "This server does not hold the answer; it pointed to the nameservers of the next zone down.") }
                    if hop.referral == nil && hop.message.rcode != "NOERROR" { RcodeBadge(rcode: hop.message.rcode) }
                    Spacer()
                }
                Text("asked \(hop.server.name) at \(hop.server.address)")
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
                    Text(ms(hop.exchange.rttMs)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).frame(width: 60, alignment: .trailing)
                }

                if let ref = hop.referral {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Image(systemName: ref.ds.isEmpty ? "lock.open" : "lock.fill").foregroundStyle(ref.ds.isEmpty ? Color.secondary : Color.yellow)
                            Text(ref.ds.isEmpty ? "hands off \(prose(ref.zone)) without a DS record (unsigned below here)" : "hands off \(prose(ref.zone)) with \(ref.ds.count) DS record\(ref.ds.count == 1 ? "" : "s")")
                                .font(.callout)
                        }
                        Text(ref.nameservers.joined(separator: "  ")).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        if !ref.glue.isEmpty {
                            Text("glue: " + ref.glue.keys.sorted().map { "\($0) → \(ref.glue[$0]!.joined(separator: ", "))" }.joined(separator: "   "))
                                .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
                        }
                    }
                    .padding(8)
                    .background(Color.secondary.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                } else if !hop.message.answer.isEmpty {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(hop.message.answer.enumerated()), id: \.offset) { _, r in
                            HStack(spacing: 8) {
                                TypeBadge(type: r.type)
                                Text(r.rdata).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                    }
                    .padding(8)
                    .background(Color.secondary.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }

                HStack {
                    Text("candidates: \(hop.candidates.count)  ·  \(hop.message.sizeBytes) B").font(.caption).foregroundStyle(.tertiary)
                    Spacer()
                    Button(showMessage ? "Hide message" : "Show message") { showMessage.toggle() }.buttonStyle(.link).font(.caption)
                }
                if showMessage {
                    Text(hop.message.text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.secondary.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }
            .padding(.bottom, isLast ? 0 : 18)
        }
    }
}
