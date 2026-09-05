import SwiftUI

/// Change log of one watch.
struct WatchView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var watches: WatchCenter
    var id: UUID

    var body: some View {
        if let w = watches.watches.first(where: { $0.id == id }) {
            VStack(spacing: 0) {
                StatusStrip {
                    Pill(text: w.paused ? "paused" : "watching", icon: w.paused ? "pause.circle" : "eye", color: w.paused ? .secondary : .accentColor,
                         help: "Nordyg re-runs this query every \(w.intervalLabel) and records every answer. A change in the answer set or rcode is logged and sent as a notification.")
                    Pill(text: "every \(w.intervalLabel)", icon: "timer", mono: true)
                    Pill(text: "\(w.changes) change\(w.changes == 1 ? "" : "s")", icon: "arrow.triangle.2.circlepath", color: w.changes > 0 ? .orange : .secondary, mono: true)
                    Pill(text: "\(w.events.count) checks", mono: true)
                    Pill(text: w.endpoint.title, icon: "server.rack")
                    Spacer()
                    HStack(spacing: 6) {
                        Text(w.question.name).font(.system(.callout, design: .monospaced))
                        TypeBadge(type: w.question.type)
                    }
                }
                Divider()
                HStack(spacing: 10) {
                    Button { watches.checkNow(id) } label: { Label("Check now", systemImage: "arrow.clockwise") }
                    Button { watches.setPaused(id, !w.paused) } label: { Label(w.paused ? "Resume" : "Pause", systemImage: w.paused ? "play" : "pause") }
                    Menu {
                        ForEach(WatchCenter.intervals, id: \.self) { s in
                            Button(WatchCenter.intervalLabel(s)) { watches.setInterval(id, s) }
                        }
                    } label: { Label("Interval", systemImage: "timer") }.fixedSize()
                    Spacer()
                    Button(role: .destructive) { watches.remove(id); model.selectedWatch = nil } label: { Label("Stop watching", systemImage: "eye.slash") }
                }
                .padding(.horizontal, 12).padding(.vertical, 8)
                Divider()
                if w.events.isEmpty {
                    ContentUnavailableView("No checks yet", systemImage: "hourglass", description: Text("The first check runs right away."))
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(w.events.enumerated()), id: \.element.id) { i, e in
                                EventRow(event: e, previous: i + 1 < w.events.count ? w.events[i + 1] : nil, isLast: i == w.events.count - 1)
                            }
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .onAppear { watches.markRead(id) }
        } else {
            ContentUnavailableView("Watch removed", systemImage: "eye.slash")
        }
    }
}

struct EventRow: View {
    var event: WatchEvent
    var previous: WatchEvent?
    var isLast: Bool

    var color: Color {
        if event.error != nil { return .red }
        return event.changed ? .orange : .green
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                Circle().fill(color).frame(width: event.changed || event.error != nil ? 12 : 8, height: event.changed || event.error != nil ? 12 : 8).padding(.top, event.changed || event.error != nil ? 4 : 6)
                if !isLast { Rectangle().fill(Color.secondary.opacity(0.25)).frame(width: 2).frame(maxHeight: .infinity) }
            }
            .frame(width: 12)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(event.date.formatted(date: .abbreviated, time: .standard)).font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                    if let err = event.error {
                        Pill(text: "error", icon: "xmark.circle", color: .red)
                        Text(err).font(.callout).foregroundStyle(.red).lineLimit(1)
                    } else {
                        RcodeBadge(rcode: event.rcode)
                        if event.changed { Pill(text: "changed", icon: "arrow.triangle.2.circlepath", color: .orange) }
                    }
                }
                if event.changed || previous == nil || event.error == nil && isLast {
                    AnswerDiff(before: previous?.answers ?? [], after: event.answers, showUnchanged: !event.changed)
                }
            }
            .padding(.bottom, isLast ? 0 : 10)
        }
    }
}

/// Removed lines in red, added in green, kept in grey.
struct AnswerDiff: View {
    var before: [String]
    var after: [String]
    var showUnchanged: Bool

    var body: some View {
        let removed = before.filter { !after.contains($0) }
        let added = after.filter { !before.contains($0) }
        let kept = after.filter { before.contains($0) }
        VStack(alignment: .leading, spacing: 1) {
            ForEach(removed, id: \.self) { Text("− \($0)").foregroundStyle(.red) }
            ForEach(added, id: \.self) { Text("+ \($0)").foregroundStyle(.green) }
            if showUnchanged { ForEach(kept, id: \.self) { Text("  \($0)").foregroundStyle(.secondary) } }
            if after.isEmpty && added.isEmpty && removed.isEmpty { Text("  (no answer records)").foregroundStyle(.secondary) }
        }
        .font(.system(.callout, design: .monospaced))
        .textSelection(.enabled)
    }
}

/// Contents of the menu bar extra.
struct WatchMenu: View {
    @EnvironmentObject var watches: WatchCenter
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if watches.watches.isEmpty {
                Text("No watches").foregroundStyle(.secondary)
                Text("In Nordyg, run a query and choose Watch from the toolbar.").font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(watches.watches) { w in
                    HStack(spacing: 8) {
                        Circle().fill(w.paused ? Color.secondary : (w.unread ? Color.orange : Color.green)).frame(width: 8, height: 8)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(w.title).font(.system(.callout, design: .monospaced))
                            Text(lastLine(w)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        Button { watches.checkNow(w.id) } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.plain).help("Check now")
                    }
                }
            }
            Divider()
            Button("Open Nordyg") {
                NSApp.activate(ignoringOtherApps: true)
                NSApp.windows.first { $0.canBecomeMain }?.makeKeyAndOrderFront(nil)
            }
        }
        .padding(12)
        .frame(width: 320)
    }

    func lastLine(_ w: Watch) -> String {
        guard let e = w.last else { return "waiting for first check" }
        let when = e.date.formatted(date: .omitted, time: .shortened)
        if let err = e.error { return "\(when) error: \(err)" }
        return "\(when) \(e.rcode) \(e.answers.isEmpty ? "" : e.answers.joined(separator: ", "))" + (w.changes > 0 ? " · \(w.changes) change\(w.changes == 1 ? "" : "s")" : "")
    }
}
