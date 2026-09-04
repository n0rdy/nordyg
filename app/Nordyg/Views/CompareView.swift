import SwiftUI

struct CompareView: View {
    var result: CompareResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Label(result.consistent ? "All resolvers agree" : "Resolvers disagree",
                          systemImage: result.consistent ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(result.consistent ? .green : .orange)
                        .font(.headline)
                    Spacer()
                    Text("\(result.questionSent.name) \(result.questionSent.type)").font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
                }
                ForEach(Array(result.groups.enumerated()), id: \.offset) { i, g in
                    GroupView(index: i, group: g, entries: result.results)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct GroupView: View {
    var index: Int
    var group: CompareGroup
    var entries: [CompareEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                if group.key == "error" {
                    Text("Failed").font(.headline).foregroundStyle(.red)
                } else {
                    RcodeBadge(rcode: group.rcode ?? "")
                    Text("\(group.members.count) resolver\(group.members.count == 1 ? "" : "s")").font(.headline)
                }
            }
            if let answers = group.answers {
                if answers.isEmpty {
                    Text("no answer records").foregroundStyle(.secondary).font(.callout)
                } else {
                    ForEach(answers, id: \.self) { a in
                        Text(a).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    }
                }
            }
            Divider()
            ForEach(group.members, id: \.self) { m in
                let e = entries[m]
                HStack(spacing: 8) {
                    Circle().fill(e.ok ? Color.green : Color.red).frame(width: 8, height: 8)
                    Text(e.endpoint.title).lineLimit(1)
                    Spacer()
                    if let x = e.exchange {
                        Text(String(format: "%.1f ms", x.rttMs)).monospacedDigit().foregroundStyle(.secondary)
                        Text(x.protocol).foregroundStyle(.secondary)
                        if let ttl = e.message?.answer.first?.ttl { Text("ttl \(ttl)").foregroundStyle(.secondary) }
                        if e.message?.flags.ad == true { Image(systemName: "lock.fill").foregroundStyle(.green).help("AD flag set by the resolver") }
                    }
                    if let err = e.error { Text("\(err.code): \(err.message)").foregroundStyle(.red).lineLimit(1).truncationMode(.middle) }
                }
                .font(.callout)
            }
        }
        .padding(12)
        .background(Color.secondary.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
