import SwiftUI

/// Trailing inspector: details of the selected record.
struct InspectorView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if let rec = model.selectedRecord {
                RecordDetail(record: rec)
            } else {
                ContentUnavailableView("No record selected", systemImage: "sidebar.trailing", description: Text("Select a row to see its fields, decoded TXT data and actions."))
            }
        }
        .navigationTitle("Record")
    }
}

struct RecordDetail: View {
    @EnvironmentObject var model: AppModel
    var record: Record

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 8) {
                    TypeBadge(type: record.type)
                    Text(record.name).font(.system(.body, design: .monospaced).weight(.semibold)).textSelection(.enabled).lineLimit(2)
                }
                Text(record.rdata).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius: 6))

                HStack(spacing: 6) {
                    Pill(text: "TTL \(record.ttl)", icon: "clock", mono: true)
                    Pill(text: record.qclass, mono: true)
                    Pill(text: "type \(record.typeCode)", mono: true)
                }

                if let fields = record.fields, !fields.isEmpty {
                    Text("Fields").font(.headline)
                    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                        ForEach(fields.keys.sorted(), id: \.self) { k in
                            GridRow {
                                Text(k).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                                Text(fields[k]!.display).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                    }
                }
                if let raw = record.raw {
                    Text("Unknown type; raw rdata").font(.headline)
                    Text(raw).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                }
                if let decoded = record.decoded {
                    Text("Decoded").font(.headline)
                    DecodedTXTView(decoded: decoded)
                }

                Text("Actions").font(.headline)
                VStack(alignment: .leading, spacing: 6) {
                    Button { Pasteboard.copy(record.rdata) } label: { Label("Copy data", systemImage: "doc.on.doc") }
                    Button { Pasteboard.copy("\(record.name) \(record.ttl) IN \(record.type) \(record.rdata)") } label: { Label("Copy record", systemImage: "doc.on.doc.fill") }
                    if let t = record.target {
                        Button { model.resolve(t) } label: { Label("Resolve \(prose(t)) (A)", systemImage: "arrow.turn.down.right") }
                        Button { model.resolve(t, type: "AAAA") } label: { Label("Resolve \(prose(t)) (AAAA)", systemImage: "arrow.turn.down.right") }
                    }
                }
                .buttonStyle(.link)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct DecodedTXTView: View {
    var decoded: JSONValue
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Pill(text: (decoded["kind"]?.stringValue ?? "decoded").uppercased(), color: .orange, mono: true)
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
                    .font(.system(.callout, design: .monospaced)).textSelection(.enabled)
            }
            if let tags = decoded["tags"]?.objectValue {
                Text(tags.keys.sorted().compactMap { k in tags[k].flatMap { $0 == .null ? nil : "\(k)=\($0.display)" } }.joined(separator: "; "))
                    .font(.system(.callout, design: .monospaced)).textSelection(.enabled)
            }
        }
        .padding(8)
        .background(Color.orange.opacity(0.07))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}
