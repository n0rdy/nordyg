import SwiftUI

struct TraceView: View {
    @EnvironmentObject var model: AppModel
    var result: TraceResult
    @State private var tab = "hops"

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $tab) {
                    Text("Hops").tag("hops")
                    Text("Final answer").tag("final")
                    Text("DNSSEC").tag("dnssec")
                }
                .pickerStyle(.segmented).frame(width: 300)
                Spacer()
                RcodeBadge(rcode: result.final.rcode)
                if let d = result.dnssec { StatusBadge(status: d.status) }
                Text("\(result.hops.count) hops, \(String(format: "%.0f", result.hops.map(\.exchange.rttMs).reduce(0, +))) ms total").font(.callout).monospacedDigit()
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            Divider()
            switch tab {
            case "final": RecordsView(messages: [result.final])
            case "dnssec": DNSSECView(result: result.dnssec)
            default:
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Array(result.hops.enumerated()), id: \.offset) { i, hop in
                            HopView(index: i, hop: hop)
                        }
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }
}

struct HopView: View {
    var index: Int
    var hop: TraceHop
    @State private var showMessage = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text("\(index + 1)").font(.caption.weight(.bold)).frame(width: 20, height: 20)
                    .background(Color.accentColor.opacity(0.2)).clipShape(Circle())
                Text(hop.zone).font(.system(.body, design: .monospaced).weight(.semibold))
                Text("via \(hop.server.name) \(hop.server.address)").foregroundStyle(.secondary)
                Spacer()
                Text(String(format: "%.1f ms", hop.exchange.rttMs)).monospacedDigit().foregroundStyle(.secondary)
                RcodeBadge(rcode: hop.message.rcode)
                if hop.message.flags.aa { Text("AA").font(.caption.weight(.bold)).foregroundStyle(.green) }
            }
            if let ref = hop.referral {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "arrow.turn.down.right").foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(ref.zone) → \(ref.nameservers.joined(separator: ", "))").font(.system(.callout, design: .monospaced))
                        if !ref.glue.isEmpty {
                            Text("glue: " + ref.glue.keys.sorted().map { "\($0) \(ref.glue[$0]!.joined(separator: " "))" }.joined(separator: "; "))
                                .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                        }
                        Text(ref.ds.isEmpty ? "no DS (unsigned delegation)" : "DS: " + ref.ds.map(\.rdata).joined(separator: "; "))
                            .font(.system(.caption, design: .monospaced)).foregroundStyle(ref.ds.isEmpty ? Color.secondary : Color.green)
                    }
                }
                .padding(.leading, 28)
            } else if !hop.message.answer.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(hop.message.answer.enumerated()), id: \.offset) { _, r in
                        Text("\(r.name) \(r.ttl) \(r.type) \(r.rdata)").font(.system(.callout, design: .monospaced))
                    }
                }
                .padding(.leading, 28)
            }
            HStack {
                Text("candidates: \(hop.candidates.joined(separator: ", "))").font(.caption).foregroundStyle(.tertiary).lineLimit(1)
                Spacer()
                Button(showMessage ? "Hide message" : "Show message") { showMessage.toggle() }.buttonStyle(.link).font(.caption)
            }
            .padding(.leading, 28)
            if showMessage {
                Text(hop.message.text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius: 6))
                    .padding(.leading, 28)
            }
        }
        .padding(10)
        .background(Color.secondary.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
