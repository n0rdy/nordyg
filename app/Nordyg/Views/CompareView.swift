import SwiftUI

struct CompareView: View {
    var result: CompareResult

    var body: some View {
        VStack(spacing: 0) {
            StatusStrip {
                Pill(text: result.consistent ? "all agree" : "disagreement",
                     icon: result.consistent ? "checkmark.circle.fill" : "exclamationmark.triangle.fill",
                     color: result.consistent ? .green : .orange,
                     help: result.consistent ? "Every resolver returned the same set of records. TTL and record order are ignored in the comparison." : "Resolvers returned different data. Common causes: a recent change still propagating, geo-based answers, or a resolver that filters or blocks the name.")
                Pill(text: "\(result.results.count) resolvers", icon: "server.rack", mono: true, help: "Resolvers queried concurrently with the same question.")
                Pill(text: "\(result.groups.filter { $0.key != "error" }.count) distinct answers", mono: true, help: "Number of different answer sets seen. One means agreement.")
                if let failed = result.groups.first(where: { $0.key == "error" }) {
                    Pill(text: "\(failed.members.count) failed", icon: "xmark.circle", color: .red, mono: true, help: "Resolvers that did not answer at all: timeout, refused connection or TLS failure. See the row for the reason.")
                }
                Spacer()
                HStack(spacing: 6) {
                    Text(result.questionSent.name).font(.system(.callout, design: .monospaced))
                    TypeBadge(type: result.questionSent.type)
                }
            }
            Divider()
            ScrollView([.vertical, .horizontal]) {
                CompareGrid(result: result)
                    .padding(16)
            }
        }
    }
}

/// Resolvers as rows, distinct answer values as columns. A filled cell means
/// the resolver returned that value; row colour follows its group.
struct CompareGrid: View {
    var result: CompareResult

    /// Distinct answer values across all groups, largest group first.
    var columns: [String] {
        var seen = Set<String>()
        var out: [String] = []
        for g in result.groups {
            for a in g.answers ?? [] where seen.insert(a).inserted { out.append(a) }
        }
        return out
    }

    func groupIndex(of member: Int) -> Int {
        result.groups.firstIndex { $0.members.contains(member) } ?? 0
    }

    static let groupColors: [Color] = [.green, .orange, .purple, .blue, .pink, .teal, .indigo, .brown]

    func color(forGroup i: Int) -> Color {
        result.groups[i].key == "error" ? .red : (i == 0 && result.consistent ? .green : Self.groupColors[i % Self.groupColors.count])
    }

    var body: some View {
        let cols = columns
        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
            GridRow {
                Text("Resolver").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text("Rcode").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text("Time").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text("TTL").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(cols, id: \.self) { c in
                    Text(c).font(.system(.caption, design: .monospaced).weight(.semibold)).lineLimit(1).truncationMode(.middle).frame(maxWidth: 200)
                }
            }
            Divider().gridCellUnsizedAxes(.horizontal)
            ForEach(Array(result.results.enumerated()), id: \.offset) { i, e in
                let gi = groupIndex(of: i)
                let c = color(forGroup: gi)
                GridRow {
                    HStack(spacing: 8) {
                        RoundedRectangle(cornerRadius: 2).fill(c).frame(width: 4, height: 18)
                        Text(e.endpoint.title).lineLimit(1)
                        if e.message?.flags.ad == true { Image(systemName: "lock.fill").foregroundStyle(.green).help("Resolver set the AD flag") }
                    }
                    if let m = e.message { RcodeBadge(rcode: m.rcode) } else { Pill(text: e.error?.code ?? "error", color: .red, mono: true) }
                    Text(e.exchange.map { ms($0.rttMs) } ?? "—").font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                    Text(e.message?.answer.first.map { "\($0.ttl)" } ?? "—").font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                    ForEach(cols, id: \.self) { col in
                        let has = e.message?.answer.contains { $0.rdata == col } ?? false
                        ZStack {
                            RoundedRectangle(cornerRadius: 4).fill(has ? c.opacity(0.22) : Color.secondary.opacity(0.05))
                            if has { Image(systemName: "checkmark").font(.caption.weight(.bold)).foregroundStyle(c) }
                        }
                        .frame(height: 24)
                    }
                }
                if let err = e.error {
                    GridRow {
                        Text(err.message).font(.caption).foregroundStyle(.red).lineLimit(2)
                            .gridCellColumns(4 + cols.count)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
