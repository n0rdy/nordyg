import SwiftUI

struct CompareView: View {
    @EnvironmentObject var model: AppModel
    var result: CompareResult

    var body: some View {
        content
            .sheet(isPresented: Binding(get: { model.compareDetail != nil }, set: { if !$0 { model.compareDetail = nil } })) {
                if let i = model.compareDetail, result.results.indices.contains(i) {
                    CompareDetailSheet(entry: result.results[i], question: result.questionSent)
                        .environmentObject(model)
                }
            }
    }

    private var content: some View {
        VStack(spacing: 0) {
            StatusStrip {
                Pill(text: result.consistent ? "all agree" : "disagreement",
                     icon: result.consistent ? "checkmark.circle.fill" : "exclamationmark.triangle.fill",
                     color: result.consistent ? .green : .orange,
                     help: result.consistent ? "Every resolver returned the same set of records. TTL and record order are ignored in the comparison." : "Resolvers returned different data. Common causes: a recent change still propagating, geo-based answers, or a resolver that filters or blocks the name.")
                Meta(text: plural(result.results.count, "resolver"), help: "Resolvers queried concurrently with the same question.")
                Dot()
                Meta(text: plural(result.groups.filter { $0.key != "error" }.count, "distinct answer"), help: "Number of different answer sets seen. One means agreement.")
                if let failed = result.groups.first(where: { $0.key == "error" }) {
                    Pill(text: "\(failed.members.count) failed", icon: "xmark.circle", color: .red, mono: true, help: "Resolvers that did not answer at all: timeout, refused connection or TLS failure. See the row for the reason.")
                }
                Spacer()
                HStack(spacing: 6) {
                    Text(prose(result.questionSent.name)).font(.system(.callout, design: .monospaced))
                    TypeBadge(type: result.questionSent.type)
                }
            }
            Divider()
            PinnedScroll {
                CompareGrid(result: result).padding(16)
            }
            if !result.consistent {
                Divider()
                HStack(spacing: 12) {
                    Image(systemName: "info.circle").foregroundStyle(.secondary)
                    let blockers = result.results.filter { CompareBlock.blocks($0, in: result) }.map(\.endpoint.title)
                    if !blockers.isEmpty {
                        // A filter, not a stale cache: purge pages would not help.
                        Text(verbatim: "\(blockers.joined(separator: ", ")) \(blockers.count == 1 ? "blocks" : "block") this name, as ad and malware filters do. The other answers are what the name really resolves to.")
                    } else {
                        Text("Answers differ. Usually a change still spreading, a CDN answering by location, or a resolver filtering the name. To clear an old copy:")
                        Link("Cloudflare", destination: URL(string: "https://one.one.one.one/purge-cache/")!)
                        Link("Google", destination: URL(string: "https://developers.google.com/speed/public-dns/cache")!)
                    }
                    Spacer()
                }
                .font(.callout)
                .padding(.horizontal, 12).padding(.vertical, 8)
            }
        }
    }
}

/// Resolvers as rows, distinct answer values as columns. A filled cell means
/// the resolver returned that value; row colour follows its group.
struct CompareGrid: View {
    @EnvironmentObject var model: AppModel
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

    /// Group colours only tell answers apart, so they avoid green, orange and
    /// red, which mean ok, warning and failure everywhere else in the app.
    static let groupColors: [Color] = [.blue, .purple, .teal, .pink, .indigo, .brown, .cyan]

    func color(forGroup i: Int) -> Color {
        let g = result.groups[i]
        if g.key == "error" { return .red }
        if result.consistent { return .green }
        // A blocked answer is the one to discount: grey, not a group hue.
        if g.members.contains(where: { CompareBlock.blocks(result.results[$0], in: result) }) { return .secondary }
        let realIndex = result.groups[..<i].filter { grp in grp.key != "error" && !grp.members.contains(where: { CompareBlock.blocks(result.results[$0], in: result) }) }.count
        return Self.groupColors[realIndex % Self.groupColors.count]
    }

    var body: some View {
        let cols = columns
        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 8) {
            GridRow {
                Text("Resolver").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text("Rcode").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text("Time").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text("TTL").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Text("Cache").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
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
                        // The name opens this resolver's full answer.
                        Button { model.compareDetail = i } label: {
                            HStack(spacing: 4) {
                                Text(e.endpoint.title).lineLimit(1).fixedSize()
                                if e.message != nil { Image(systemName: "chevron.right").font(.caption2.weight(.semibold)).foregroundStyle(.tertiary) }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .disabled(e.message == nil)
                        .help("Show everything this resolver returned")
                        // A shield, not a lock: a lock reads as an encrypted
                        // connection, which plain UDP is not.
                        if e.message?.flags.ad == true { Image(systemName: "checkmark.shield").foregroundStyle(.secondary).help("The resolver says it validated this answer with DNSSEC (AD flag).") }
                        if CompareBlock.blocks(e, in: result) { Pill(text: "blocks", color: .orange, help: "This resolver says it filters the name (Extended DNS Error), or answers with a null address while others resolve it: an ad or malware blocker.").fixedSize() }
                    }
                    if let m = e.message { RcodeBadge(rcode: m.rcode) } else { Pill(text: e.error?.code ?? "error", color: .red, mono: true) }
                    Text(e.exchange.map { ms($0.rttMs) } ?? "—").font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                    Text(verbatim: e.message?.answer.first(where: { $0.type != "RRSIG" }).map { String($0.ttl) } ?? "—").font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                    if let m = e.message, m.rcode == "NOERROR" {
                        HStack(spacing: 4) {
                            CacheAgePill(message: m, question: result.questionSent)
                            if m.isStale { StalePill() }
                        }
                    } else {
                        Text("—").foregroundStyle(.secondary)
                    }
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
                        // Words for the failure; the raw error (with local
                        // addresses in it) only on hover.
                        Text(RunErrorView.describe(err.code).0).font(.caption).foregroundStyle(.red).lineLimit(1)
                            .help(err.message)
                            .gridCellColumns(5 + cols.count)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Telling a filtering resolver from a disagreeing one.
enum CompareBlock {
    static let nullAddresses: Set<String> = ["0.0.0.0", "::", "127.0.0.1", "::1"]

    /// A resolver blocks the name when it says so (EDE 15–18), or answers only
    /// null addresses while another resolver returns real records. A bare
    /// NXDOMAIN is not enough: it is also what a resolver still caching the
    /// absence of a newly created name returns.
    static func blocks(_ e: CompareEntry, in result: CompareResult) -> Bool {
        guard let m = e.message else { return false }
        if m.isFiltered { return true }
        let othersResolve = result.results.contains { o in
            guard let om = o.message, om.rcode == "NOERROR" else { return false }
            return om.answer.contains { ($0.type == "A" || $0.type == "AAAA") && !nullAddresses.contains($0.rdata) }
        }
        guard othersResolve else { return false }
        let addrs = m.answer.filter { $0.type == "A" || $0.type == "AAAA" }.map(\.rdata)
        return !addrs.isEmpty && addrs.allSatisfy { nullAddresses.contains($0) }
    }
}

/// One compared resolver's full answer, in the same view Query uses.
struct CompareDetailSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var entry: CompareEntry
    var question: Question

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Label(entry.endpoint.title, systemImage: "server.rack").font(.headline)
                Text(entry.endpoint.summary).foregroundStyle(.secondary).font(.callout)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            .padding(12)
            Divider()
            if let m = entry.message, let ex = entry.exchange {
                QueryResultView(results: [QueryResult(questionSent: question, message: m, exchange: ex, dnssec: nil)], offersOtherResolvers: false)
            }
        }
        .frame(minWidth: 860, minHeight: 560)
    }
}
