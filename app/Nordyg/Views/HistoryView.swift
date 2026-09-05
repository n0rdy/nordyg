import SwiftUI

struct HistoryView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var watches: WatchCenter
    @State private var filter = ""

    var items: [HistoryItem] {
        let f = filter.trimmingCharacters(in: .whitespaces).lowercased()
        let list = f.isEmpty ? model.history : model.history.filter { $0.name.lowercased().contains(f) }
        return list.sorted { ($0.pinned ? 1 : 0, $0.date) > ($1.pinned ? 1 : 0, $1.date) }
    }

    var body: some View {
        VStack(spacing: 0) {
            List {
                if !watches.watches.isEmpty {
                    Section("Watches") {
                        ForEach(watches.watches) { w in
                            Button { model.selectedWatch = w.id } label: {
                                HStack(spacing: 8) {
                                    Circle().fill(w.paused ? Color.secondary : (w.unread ? Color.orange : Color.green)).frame(width: 8, height: 8)
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 6) {
                                            Text(w.question.name).font(.system(.body, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                                            Text(w.question.type).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                                        }
                                        Text("every \(w.intervalLabel)" + (w.changes > 0 ? " · \(w.changes) change\(w.changes == 1 ? "" : "s")" : "") + (w.paused ? " · paused" : "")).font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .listRowBackground(model.selectedWatch == w.id ? Color.accentColor.opacity(0.15) : nil)
                            .contextMenu {
                                Button("Check now") { watches.checkNow(w.id) }
                                Button(w.paused ? "Resume" : "Pause") { watches.setPaused(w.id, !w.paused) }
                                Button("Stop watching", role: .destructive) { watches.remove(w.id); if model.selectedWatch == w.id { model.selectedWatch = nil } }
                            }
                        }
                    }
                }
                Section(watches.watches.isEmpty ? "" : "History") {
                ForEach(items) { item in
                    Button { model.rerun(item) } label: {
                        HStack(spacing: 6) {
                            if item.pinned { Image(systemName: "pin.fill").font(.caption).foregroundStyle(.secondary) }
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(item.name).font(.system(.body, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                                    Text(item.type).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                                }
                                Text(item.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Spacer()
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .contextMenu {
                        Button(item.pinned ? "Unpin" : "Pin") { model.togglePin(item) }
                        Button("Delete") { model.delete(item) }
                    }
                }
                }
            }
            .listStyle(.sidebar)
            .overlay {
                if model.history.isEmpty && watches.watches.isEmpty {
                    Text("No history yet").foregroundStyle(.secondary)
                }
            }
            Divider()
            HStack {
                TextField("Filter", text: $filter).textFieldStyle(.roundedBorder)
                Button { model.clearHistory() } label: { Image(systemName: "trash") }
                    .help("Clear unpinned history")
                    .disabled(model.history.isEmpty)
            }
            .padding(8)
        }
        .navigationTitle("History")
    }
}
