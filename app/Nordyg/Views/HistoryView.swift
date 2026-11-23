import SwiftUI

struct HistoryView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var watches: WatchCenter
    @State private var filter = ""
    private var modeFilter: Mode? {
        get { model.historyFilter }
        nonmutating set { model.historyFilter = newValue }
    }

    var items: [HistoryItem] {
        let f = filter.trimmingCharacters(in: .whitespaces).lowercased()
        let list = model.history.filter { item in
            (modeFilter == nil || item.mode == modeFilter?.rawValue || (modeFilter == .query && item.mode == "compare")) &&
            (f.isEmpty || item.name.lowercased().contains(f) || item.type.lowercased().contains(f) || item.subtitle.lowercased().contains(f))
        }
        return list.sorted { ($0.pinned ? 1 : 0, $0.date) > ($1.pinned ? 1 : 0, $1.date) }
    }

    private func count(_ m: Mode) -> Int { model.history.filter { $0.mode == m.rawValue || (m == .query && $0.mode == "compare") }.count }

    /// Watches are Query lookups, so a filter on another mode hides them.
    private var showWatches: Bool { !watches.watches.isEmpty && (modeFilter == nil || modeFilter == .query) }

    var body: some View {
        VStack(spacing: 0) {
            List {
                if showWatches {
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
                                        Text(verbatim: "every \(w.intervalLabel)" + (w.changes > 0 ? " · \(w.changes) change\(w.changes == 1 ? "" : "s")" : "") + (w.paused ? " · paused" : "")).font(.caption).foregroundStyle(.secondary)
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
                if let m = modeFilter {
                    // A visible header with a way out, so an active filter is
                    // never mistaken for missing history.
                    Section {
                        EmptyView()
                    } header: {
                        HStack {
                            Text(verbatim: "Showing \(m.title) only")
                            Spacer()
                            Button { modeFilter = nil } label: { Image(systemName: "xmark.circle.fill") }
                                .buttonStyle(.plain)
                                .foregroundStyle(.secondary)
                                .help("Show all history")
                        }
                    }
                }
                ForEach(HistorySections.group(items), id: \.title) { section in
                    Section(section.title) {
                        ForEach(section.items) { item in
                            HistoryRow(item: item, showsTime: section.showsTime)
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            .overlay {
                if model.history.isEmpty && watches.watches.isEmpty {
                    Text("No history yet").foregroundStyle(.secondary)
                } else if !model.history.isEmpty && items.isEmpty {
                    VStack(spacing: 6) {
                        Text("No matches").foregroundStyle(.secondary)
                        Button("Show all") { filter = ""; modeFilter = nil }.buttonStyle(.link)
                    }
                }
            }
            if !model.history.isEmpty {
                Divider()
                HStack(spacing: 6) {
                    TextField("Search", text: $filter).textFieldStyle(.roundedBorder)
                    Menu {
                        Picker("Show", selection: $model.historyFilter) {
                            Text("All").tag(Mode?.none)
                            Divider()
                            ForEach(Mode.allCases) { m in
                                let n = count(m)
                                Text(verbatim: n > 0 ? "\(m.title) (\(n))" : m.title).tag(Mode?.some(m))
                                    .disabled(n == 0)
                            }
                        }
                        .pickerStyle(.inline)
                    } label: {
                        Image(systemName: modeFilter == nil ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
                            .foregroundStyle(modeFilter == nil ? Color.secondary : Color.accentColor)
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .help(modeFilter.map { "Showing \($0.title) only" } ?? "Show one kind of history")
                    Button { model.clearHistory() } label: { Image(systemName: "trash") }
                        .buttonStyle(.borderless)
                        .help("Clear unpinned history")
                }
                .padding(8)
            }
        }
        .navigationTitle("History")
    }
}

/// One history entry on one line: what was asked (mode icon), of what, and
/// when. The resolver shows only when it is not the default; the tooltip has
/// everything.
struct HistoryRow: View {
    @EnvironmentObject var model: AppModel
    var item: HistoryItem
    var showsTime: Bool

    var body: some View {
        Button { model.rerun(item) } label: {
            HStack(spacing: 7) {
                Image(systemName: icon)
                    .foregroundStyle(.secondary)
                    .frame(width: 16)
                Text(item.name)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle)
                if let t = recordType {
                    Text(t).font(.caption.weight(.semibold)).foregroundStyle(TypeStyle.color(t))
                }
                if let r = resolverNote {
                    Text(r).font(.caption).foregroundStyle(.tertiary).lineLimit(1)
                }
                Spacer(minLength: 4)
                Text(stamp).font(.caption.monospacedDigit()).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(tooltip)
        .contextMenu {
            Button(item.pinned ? "Unpin" : "Pin") { model.togglePin(item) }
            Button("Delete") { model.delete(item) }
        }
    }

    private var mode: Mode { item.mode == "compare" ? .query : (Mode(rawValue: item.mode) ?? .query) }
    private var icon: String { item.mode == "compare" ? "checklist" : mode.icon }

    /// Only Query and Trace have a real record type; MAIL/RDAP/ZONE were stand-ins.
    private var recordType: String? { mode == .query || mode == .trace ? item.type : nil }

    private var resolverNote: String? {
        if item.mode == "compare" { return "several resolvers" }
        guard let ep = item.endpoint, ep != model.systemEndpoints.first else { return nil }
        return ep.title
    }

    private var stamp: String {
        showsTime ? item.date.formatted(date: .omitted, time: .shortened) : item.date.formatted(.dateTime.day().month(.abbreviated))
    }

    private var tooltip: String {
        var parts = [item.mode == "compare" ? "Query, several resolvers" : mode.title, item.name]
        if let t = recordType { parts.append(t) }
        if item.mode != "compare", let ep = item.endpoint { parts.append("via \(ep.title)") }
        if mode == .trace { parts.append("from the root") }
        return parts.joined(separator: " ") + ", " + item.date.formatted(date: .abbreviated, time: .shortened)
    }
}

/// Pinned first, then Today, Yesterday, the rest of the past week by day, and
/// older entries by month.
enum HistorySections {
    struct Section { var title: String; var items: [HistoryItem]; var showsTime: Bool }

    static func group(_ items: [HistoryItem], now: Date = Date(), calendar: Calendar = .current) -> [Section] {
        var out: [Section] = []
        let pinned = items.filter(\.pinned).sorted { $0.date > $1.date }
        if !pinned.isEmpty { out.append(Section(title: "Pinned", items: pinned, showsTime: false)) }
        let weekAgo = calendar.date(byAdding: .day, value: -6, to: calendar.startOfDay(for: now))!
        for item in items.filter({ !$0.pinned }).sorted(by: { $0.date > $1.date }) {
            let (title, showsTime): (String, Bool)
            if calendar.isDateInToday(item.date) {
                (title, showsTime) = ("Today", true)
            } else if calendar.isDateInYesterday(item.date) {
                (title, showsTime) = ("Yesterday", true)
            } else if item.date >= weekAgo {
                (title, showsTime) = (item.date.formatted(.dateTime.weekday(.wide).day().month(.wide)), true)
            } else {
                (title, showsTime) = (item.date.formatted(.dateTime.month(.wide).year()), false)
            }
            if out.last?.title == title {
                out[out.count - 1].items.append(item)
            } else {
                out.append(Section(title: title, items: [item], showsTime: showsTime))
            }
        }
        return out
    }
}
