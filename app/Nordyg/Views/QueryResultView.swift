import SwiftUI

struct QueryResultView: View {
    @EnvironmentObject var model: AppModel
    var results: [QueryResult]
    @State private var tab = "records"

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $tab) {
                    Text("Records").tag("records")
                    Text("Details").tag("details")
                    Text("DNSSEC").tag("dnssec")
                    Text("Raw").tag("raw")
                }
                .pickerStyle(.segmented)
                .frame(width: 320)
                Spacer()
                SummaryLine(results: results)
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            Divider()
            switch tab {
            case "details": DetailsView(result: results[0])
            case "dnssec": DNSSECView(result: results.first?.dnssec)
            case "raw": RawView(text: results.map(\.message.text).joined(separator: "\n\n"))
            default: RecordsView(messages: results.map(\.message))
            }
        }
    }
}

struct SummaryLine: View {
    var results: [QueryResult]
    var body: some View {
        let r = results[0]
        HStack(spacing: 12) {
            RcodeBadge(rcode: r.message.rcode)
            if let d = r.dnssec { StatusBadge(status: d.status) }
            Text(String(format: "%.1f ms", results.map(\.exchange.rttMs).max() ?? 0)).monospacedDigit()
            Text(r.exchange.endpoint.title).foregroundStyle(.secondary).lineLimit(1)
            if r.exchange.truncatedRetry { Text("TC → TCP").foregroundStyle(.secondary) }
        }
        .font(.callout)
    }
}

struct RcodeBadge: View {
    var rcode: String
    var body: some View {
        Text(rcode)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background((rcode == "NOERROR" ? Color.green : rcode == "NXDOMAIN" ? Color.orange : Color.red).opacity(0.2))
            .clipShape(Capsule())
    }
}

struct StatusBadge: View {
    var status: String
    var body: some View {
        Label(DNSSECWording.label(status), systemImage: icon)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.2))
            .clipShape(Capsule())
    }
    var color: Color {
        switch status {
        case "secure": return .green
        case "insecure": return .gray
        case "bogus": return .red
        default: return .orange
        }
    }
    var icon: String {
        switch status {
        case "secure": return "lock.fill"
        case "insecure": return "lock.open"
        case "bogus": return "xmark.shield.fill"
        default: return "questionmark.circle"
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
            VStack(spacing: 6) {
                Text("No records").font(.title3).foregroundStyle(.secondary)
                if let m = messages.first, m.rcode != "NOERROR" { Text(m.rcode).foregroundStyle(.secondary) }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            VSplitView {
                recordTable(rows)
                    .frame(minHeight: 140, maxHeight: .infinity)
                if let id = selection, let row = rows.first(where: { $0.id == id }) {
                    RecordDetail(record: row.record) { selection = nil }
                        .frame(minHeight: 90, idealHeight: 200, maxHeight: .infinity)
                }
            }
            .onExitCommand { selection = nil }
        }
    }

    @ViewBuilder
    private func recordTable(_ rows: [RecordRow]) -> some View {
        Table(rows, selection: $selection) {
            TableColumn("Section") { Text($0.section).foregroundStyle(.secondary) }.width(min: 60, ideal: 80, max: 100)
            TableColumn("Name") { Text($0.record.name).font(.system(.body, design: .monospaced)) }.width(min: 120, ideal: 220)
            TableColumn("TTL") { Text("\($0.record.ttl)").monospacedDigit() }.width(min: 50, ideal: 64, max: 90)
            TableColumn("Type") { Text($0.record.type).font(.system(.body, design: .monospaced)) }.width(min: 50, ideal: 70, max: 100)
            TableColumn("Data") { row in
                HStack(spacing: 6) {
                    Text(row.record.rdata).font(.system(.body, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                    if row.record.decoded != nil { Image(systemName: "text.magnifyingglass").foregroundStyle(.secondary) }
                }
            }
        }
        .contextMenu(forSelectionType: RecordRow.ID.self) { ids in
            if let id = ids.first, let row = rows.first(where: { $0.id == id }) {
                Button("Copy data") { Pasteboard.copy(row.record.rdata) }
                Button("Copy record") { Pasteboard.copy("\(row.record.name) \(row.record.ttl) IN \(row.record.type) \(row.record.rdata)") }
                if let t = row.record.target {
                    Divider()
                    Button("Resolve \(t) (A)") { model.resolve(t) }
                    Button("Resolve \(t) (AAAA)") { model.resolve(t, type: "AAAA") }
                }
            }
        }
    }
}

struct RecordDetail: View {
    var record: Record
    var close: () -> Void
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("\(record.type) record").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                Button { close() } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                    .buttonStyle(.plain)
                    .help("Close (Esc)")
            }
            .padding(.horizontal, 12).padding(.vertical, 6)
            Divider()
            detail
        }
    }

    private var detail: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                Text("\(record.name) \(record.ttl) \(record.qclass) \(record.type) \(record.rdata)")
                    .font(.system(.body, design: .monospaced)).textSelection(.enabled)
                if let fields = record.fields, !fields.isEmpty {
                    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 3) {
                        ForEach(fields.keys.sorted(), id: \.self) { k in
                            GridRow {
                                Text(k).foregroundStyle(.secondary)
                                Text(fields[k]!.display).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                    }
                }
                if let raw = record.raw {
                    Text("Unknown type, raw rdata: \(raw)").font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                }
                if let decoded = record.decoded {
                    DecodedTXTView(decoded: decoded)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct DecodedTXTView: View {
    var decoded: JSONValue
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text((decoded["kind"]?.stringValue ?? "decoded").uppercased()).font(.caption.weight(.bold))
                if let bits = decoded["key_bits"] { Text("\(bits.display)-bit \(decoded["key_type"]?.display ?? "")").font(.caption) }
                if let n = decoded["lookup_count"] { Text("\(n.display)/10 lookups").font(.caption) }
            }
            if let problems = decoded["problems"]?.arrayValue, !problems.isEmpty {
                ForEach(Array(problems.enumerated()), id: \.offset) { _, p in
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: severityIcon(p["severity"]?.stringValue ?? "info"))
                            .foregroundStyle(severityColor(p["severity"]?.stringValue ?? "info"))
                        Text(p["message"]?.display ?? "").textSelection(.enabled)
                    }
                    .font(.callout)
                }
            } else {
                Label("No problems found", systemImage: "checkmark.circle").foregroundStyle(.green).font(.callout)
            }
            if let mechs = decoded["mechanisms"]?.arrayValue {
                Text(mechs.map { "\($0["qualifier"]?.display ?? "")\($0["kind"]?.display ?? "")\(($0["value"]?.stringValue).map { ":" + $0 } ?? "")" }.joined(separator: "  "))
                    .font(.system(.callout, design: .monospaced))
            }
            if let tags = decoded["tags"]?.objectValue {
                Text(tags.keys.sorted().compactMap { k in tags[k].flatMap { $0 == .null ? nil : "\(k)=\($0.display)" } }.joined(separator: "; "))
                    .font(.system(.callout, design: .monospaced))
            }
        }
        .padding(8)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

func severityIcon(_ s: String) -> String {
    switch s { case "error": return "xmark.octagon.fill"; case "warning": return "exclamationmark.triangle.fill"; default: return "info.circle" }
}
func severityColor(_ s: String) -> Color {
    switch s { case "error": return .red; case "warning": return .orange; default: return .secondary }
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
                Button("Copy") { Pasteboard.copy(text) }.padding(8)
            }
        }
    }
}
