import SwiftUI

extension QueryResultView {
    static func sameName(_ a: String, _ b: String) -> Bool {
        func norm(_ s: String) -> String { s.lowercased().hasSuffix(".") ? String(s.lowercased().dropLast()) : s.lowercased() }
        return norm(a) == norm(b)
    }
}

struct QueryResultView: View {
    @EnvironmentObject var model: AppModel
    var results: [QueryResult]
    /// Offer "ask other resolvers" (off inside the several-resolvers sheet).
    var offersOtherResolvers = true
    private var tab: Binding<String> {
        Binding(get: { model.resultTabs[.query] ?? "records" }, set: { model.resultTabs[.query] = $0 })
    }

    var body: some View {
        let r = results[0]
        VStack(spacing: 0) {
            StatusStrip {
                RcodeBadge(rcode: r.message.rcode)
                if let d = r.dnssec { StatusBadge(status: d.status) }
                if r.message.isStale { StalePill() }
                // What dig prints in its header, as one quiet sentence. Only
                // flags that tell you something are named, in words; the full
                // set is in Details.
                Meta(text: "\(ms(results.map(\.exchange.rttMs).max() ?? 0)) over \(TransportName.display(r.exchange.protocol)) from \(r.exchange.endpoint.title)" + (r.exchange.truncatedRetry ? " (retried after truncation)" : ""),
                     help: Glossary.latency + "\n\n" + Glossary.transport(r.exchange.protocol, truncated: r.exchange.truncatedRetry) + "\n\n" + Glossary.server + " " + r.exchange.endpoint.summary)
                Dot()
                Meta(text: "\(r.message.sizeBytes) bytes", help: Glossary.size)
                ForEach(FlagNotes.notes(r.message.flags), id: \.self) { note in
                    Dot()
                    Meta(text: note, help: Glossary.flags(r.message.flags.set))
                }
                if results.count == 1, r.message.rcode == "NOERROR", r.exchange.endpoint.transport != "" {
                    Dot()
                    CacheAgePill(message: r.message, question: r.questionSent)
                }
                if model.systemView != nil, Self.sameName(model.systemViewName, r.questionSent.name) {
                    Dot()
                    SystemViewPill(system: model.systemView, answers: results.flatMap(\.message.addresses))
                }
                // Where "is it the same elsewhere?" comes up. Not for ALL,
                // which is a one-resolver type.
                if offersOtherResolvers, results.count == 1 {
                    Dot()
                    Button("ask other resolvers") { model.askOtherResolvers(including: r.exchange.endpoint) }
                        .buttonStyle(.link)
                        .font(.caption)
                        .help("Ask the same question of several resolvers and compare the answers")
                }
            }
            Divider()
            TabRow {
                Picker("", selection: tab) {
                    Text("Records").tag("records")
                    Text("Details").tag("details")
                    Text("DNSSEC").tag("dnssec")
                    Text("Raw").tag("raw")
                }
            }
            Divider()
            switch tab.wrappedValue {
            case "details": DetailsView(result: r)
            case "dnssec": DNSSECView(result: r.dnssec)
            case "raw": RawView(text: results.map(\.message.text).joined(separator: "\n\n"))
            default: RecordsView(messages: results.map(\.message))
            }
        }
    }
}

// MARK: records

struct RecordRow: Identifiable, Hashable {
    var id: Int
    var section: String
    var record: Record
}

struct RecordsView: View {
    @EnvironmentObject var model: AppModel
    var messages: [Message]
    @State private var selection: RecordRow.ID?

    var rows: [RecordRow] {
        var out: [RecordRow] = []
        var i = 0
        for m in messages {
            for (sec, recs) in [("Answer", m.answer), ("Authority", m.authority), ("Additional", m.additional)] {
                for r in recs { out.append(RecordRow(id: i, section: sec, record: r)); i += 1 }
            }
        }
        return out
    }

    var body: some View {
        let rows = self.rows
        if rows.isEmpty {
            ContentUnavailableView {
                Label(messages.first?.rcode == "NXDOMAIN" ? "Name does not exist" : "No records", systemImage: "tray")
            } description: {
                Text(verbatim: messages.first.map { "\($0.rcode): the server answered, but with no records for this name and type." } ?? "")
            }
        } else {
            // With a record selected, the table takes the height its rows need
            // (at most half), and the detail gets the rest: a fixed split left
            // three rows with most of the window and the detail squeezed below.
            GeometryReader { geo in
                let selected = selection.flatMap { id in rows.first { $0.id == id } }
                VStack(spacing: 0) {
                    table(rows)
                        .frame(height: selected == nil ? geo.size.height : min(Self.tableHeight(rows.count), geo.size.height / 2))
                    if let row = selected {
                        Divider()
                        RecordDetail(record: row.record) { selection = nil }
                            .frame(maxHeight: .infinity)
                    }
                }
            }
            .onExitCommand { selection = nil }
            #if DEBUG
            .onReceive(NotificationCenter.default.publisher(for: DebugHooks.selectRecord)) { note in
                let i = note.object as? Int
                selection = i.flatMap { rows.indices.contains($0) ? rows[$0].id : nil }
            }
            #endif
        }
    }

    /// Header plus rows at the table's row height, with a little slack.
    static func tableHeight(_ count: Int) -> CGFloat { max(120, 30 + CGFloat(count) * 26 + 10) }

    @ViewBuilder
    private func table(_ rows: [RecordRow]) -> some View {
            Table(rows, selection: $selection) {
                TableColumn("Section") { Text($0.section).foregroundStyle(.secondary) }.width(min: 60, ideal: 78, max: 100)
                TableColumn("Type") { TypeBadge(type: $0.record.type) }.width(min: 60, ideal: 72, max: 110)
                TableColumn("Name") { Text($0.record.name).font(.system(.body, design: .monospaced)) }.width(min: 120, ideal: 220)
                TableColumn("TTL") { Text(verbatim: "\($0.record.ttl)").monospacedDigit().foregroundStyle(.secondary) }.width(min: 50, ideal: 64, max: 90)
                TableColumn("Data") { row in
                    HStack(spacing: 6) {
                        Text(row.record.rdata).font(.system(.body, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                        if row.record.decoded != nil { Image(systemName: "text.magnifyingglass").foregroundStyle(.orange).help("Decoded, select the row for details") }
                    }
                }
            }
            // Stripes fill the empty space under a short answer with a grid of
            // blank rows; without them three records read as three records.
            .alternatingRowBackgrounds(.disabled)
            .contextMenu(forSelectionType: RecordRow.ID.self) { ids in
                if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                    Button("Copy data") { Pasteboard.copy(row.record.rdata) }
                    Button("Copy record") { Pasteboard.copy("\(row.record.name) \(row.record.ttl) IN \(row.record.type) \(row.record.rdata)") }
                    if let t = row.record.target {
                        Divider()
                        Button("Resolve \(prose(t)) (A)") { model.resolve(t) }
                        Button("Resolve \(prose(t)) (AAAA)") { model.resolve(t, type: "AAAA") }
                    }
                }
            } primaryAction: { ids in
                if let id = ids.first, let row = rows.first(where: { $0.id == id }), let t = row.record.target { model.resolve(t) }
            }
    }
}

// MARK: raw

struct RawView: View {
    var text: String
    var body: some View {
        VStack(alignment: .trailing, spacing: 0) {
            // Pinned to the top-left: a two-axis ScrollView centres content
            // smaller than itself. Lines keep their full width and scroll
            // sideways, like a terminal, instead of being cut off.
            GeometryReader { geo in
                ScrollView([.vertical, .horizontal]) {
                    Text(text)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize()
                        .padding(12)
                        .frame(minWidth: geo.size.width, minHeight: geo.size.height, alignment: .topLeading)
                }
            }
            Divider()
            HStack {
                Spacer()
                Button { Pasteboard.copy(text) } label: { Label("Copy", systemImage: "doc.on.doc") }.padding(8)
            }
        }
    }
}
