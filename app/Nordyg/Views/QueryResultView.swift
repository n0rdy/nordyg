import SwiftUI

struct QueryResultView: View {
    @EnvironmentObject var model: AppModel
    var results: [QueryResult]
    @State private var tab = "records"

    var body: some View {
        let r = results[0]
        VStack(spacing: 0) {
            StatusStrip {
                RcodeBadge(rcode: r.message.rcode)
                if let d = r.dnssec { StatusBadge(status: d.status) }
                Pill(text: ms(results.map(\.exchange.rttMs).max() ?? 0), icon: "timer", mono: true, help: Glossary.latency)
                Pill(text: r.exchange.protocol.uppercased() + (r.exchange.truncatedRetry ? " after TC" : ""), icon: "arrow.left.arrow.right", color: .accentColor, mono: true, help: Glossary.transport(r.exchange.protocol, truncated: r.exchange.truncatedRetry))
                Pill(text: r.exchange.endpoint.title, icon: "server.rack", help: Glossary.server + " " + r.exchange.endpoint.summary)
                Pill(text: "\(r.message.sizeBytes) B", mono: true, help: Glossary.size)
                Pill(text: r.message.flags.set.joined(separator: " "), mono: true, help: Glossary.flags(r.message.flags.set))
                Spacer()
                Picker("", selection: $tab) {
                    Text("Records").tag("records")
                    Text("Details").tag("details")
                    Text("DNSSEC").tag("dnssec")
                    Text("Raw").tag("raw")
                }
                .pickerStyle(.segmented)
                .frame(width: 300)
            }
            Divider()
            switch tab {
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
                Text(messages.first.map { "\($0.rcode): the server answered, but with no records for this name and type." } ?? "")
            }
        } else {
            Table(rows, selection: $selection) {
                TableColumn("Section") { Text($0.section).foregroundStyle(.secondary) }.width(min: 60, ideal: 78, max: 100)
                TableColumn("Type") { TypeBadge(type: $0.record.type) }.width(min: 60, ideal: 72, max: 110)
                TableColumn("Name") { Text($0.record.name).font(.system(.body, design: .monospaced)) }.width(min: 120, ideal: 220)
                TableColumn("TTL") { Text("\($0.record.ttl)").monospacedDigit().foregroundStyle(.secondary) }.width(min: 50, ideal: 64, max: 90)
                TableColumn("Data") { row in
                    HStack(spacing: 6) {
                        Text(row.record.rdata).font(.system(.body, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                        if row.record.decoded != nil { Image(systemName: "text.magnifyingglass").foregroundStyle(.orange).help("Decoded, see inspector") }
                    }
                }
            }
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
            .onChange(of: selection) { _, new in
                model.selectedRecord = new.flatMap { id in rows.first { $0.id == id }?.record }
                if new != nil { model.showInspector = true }
            }
            .onAppear { model.selectedRecord = nil }
        }
    }
}

// MARK: raw

struct RawView: View {
    var text: String
    var body: some View {
        VStack(alignment: .trailing, spacing: 0) {
            ScrollView([.vertical, .horizontal]) {
                Text(text)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            HStack {
                Spacer()
                Button { Pasteboard.copy(text) } label: { Label("Copy", systemImage: "doc.on.doc") }.padding(8)
            }
        }
    }
}
