import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        NavigationSplitView {
            HistoryView()
                .navigationSplitViewColumnWidth(min: 200, ideal: 240)
        } detail: {
            VStack(spacing: 0) {
                QueryBar()
                Divider()
                if let err = model.errorMessage {
                    ErrorBanner(text: err)
                }
                ResultArea()
            }
        }
        .sheet(isPresented: $model.showMacResolvers) {
            MacResolversSheet(monitor: model.macDNS).environmentObject(model)
        }
        .toolbar {
            ToolbarItem(placement: .principal) {
                ModeSwitcher(mode: $model.mode)
            }
            if model.mode == .query && !model.severalResolvers {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        WatchIntervalButtons(model: model)
                    } label: {
                        Label("Watch", systemImage: "eye")
                    }
                    .help("Re-run this query on a schedule and get notified when the answer changes")
                    .disabled(!model.canWatch)
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button { model.clearResult() } label: {
                    Label("Clear", systemImage: "xmark.circle")
                }
                .help("Clear this tab's result (⌘K)")
                .disabled(!model.canClear)
            }
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    ExportMenu()
                } label: {
                    Label("Copy as", systemImage: "doc.on.doc")
                }
                .disabled(model.outcome == nil && (model.name.isEmpty || model.commandFormats.isEmpty))
            }
        }
    }
}

/// The mode switcher in the toolbar. A native segmented picker there is drawn
/// in the toolbar's glass style with a faint grey selection that ignores the
/// tint, so this is plain buttons with the selection filled in the accent.
/// ⌘1…⌘5 switch modes.
struct ModeSwitcher: View {
    @Binding var mode: Mode

    var body: some View {
        HStack(spacing: 2) {
            ForEach(Array(Mode.allCases.enumerated()), id: \.element) { i, m in
                let selected = m == mode
                Button { mode = m } label: {
                    Text(m.title)
                        .padding(.horizontal, 12).padding(.vertical, 4)
                        .foregroundStyle(selected ? Color.white : Color.primary)
                        .background(Capsule().fill(selected ? Color.accentColor : Color.clear))
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .keyboardShortcut(KeyEquivalent(Character(String(i + 1))), modifiers: .command)
                .help("\(m.summary) (⌘\(i + 1))")
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(3)
        .fixedSize()
    }
}

struct ErrorBanner: View {
    var text: String
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            Text(text).textSelection(.enabled).lineLimit(3)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(Color.orange.opacity(0.12))
    }
}

struct ResultArea: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if let id = model.selectedWatch {
                WatchView(id: id)
            } else {
                // Each tab shows its own last result, or its explanation.
                switch model.outcome {
                case .none:
                    if let e = model.runErrors[model.mode], model.runningMode != model.mode {
                        RunErrorView(error: e)
                    } else {
                        Placeholder(running: model.runningMode == model.mode, mode: model.mode)
                    }
                case .query(let results):
                    QueryResultView(results: results)
                case .compare(let r):
                    CompareView(result: r)
                case .trace(let r):
                    TraceView(result: r)
                case .email(let r):
                    EmailView(result: r)
                case .registry(let r):
                    RegistryView(result: r)
                case .health(let r):
                    HealthView(result: r)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // While this tab re-runs, the old result must not pass for the new
        // one: no clicks on it, and (after a beat) dimmed under a progress note.
        .allowsHitTesting(!(model.runningMode == model.mode && model.outcome != nil))
        .overlay {
            if model.selectedWatch == nil, model.runningMode == model.mode, model.outcome != nil {
                RunningOverlay(name: model.runningName, mode: model.mode) { model.cancel() }
            }
        }
        .id(model.selectedWatch?.hashValue ?? model.resultVersion)
        .transition(.opacity)
        .modifier(ResultAnimation(value: model.resultVersion))
    }
}

/// A failed run, in the result area: what went wrong in words, the core's
/// own message, and what to try next.
struct RunErrorView: View {
    var error: CoreError
    var body: some View {
        let (title, icon, hint) = RunErrorView.describe(error.code)
        ContentUnavailableView {
            Label(title, systemImage: icon)
        } description: {
            VStack(spacing: 10) {
                Text(error.message.capitalizedFirst).textSelection(.enabled)
                if let hint { Text(hint).foregroundStyle(.tertiary) }
            }
            .frame(maxWidth: 520)
        }
    }

    static func describe(_ code: String) -> (String, String, String?) {
        switch code {
        case "bad_request", "unknown_type":
            return ("Check what you typed", "character.cursor.ibeam", "Fix the name or type and press ⌘↩ again.")
        case "timeout":
            return ("No answer in time", "clock.badge.exclamationmark", "The server did not reply before the timeout. Run again, raise the timeout in the options, or pick another resolver.")
        case "network":
            return ("Could not reach the server", "network.slash", "Check the connection, or whether a VPN or firewall blocks this resolver.")
        case "tls":
            return ("Secure connection failed", "lock.trianglebadge.exclamationmark", "The resolver's certificate did not check out. Check the TLS name of a custom resolver.")
        case "http":
            return ("The DoH server refused", "exclamationmark.icloud", "The DNS-over-HTTPS server answered with an HTTP error. Check the URL of a custom resolver.")
        case "resolver_unreachable":
            return ("The resolver does not answer", "server.rack", "Pick another resolver in the menu next to the name, or check the network, a VPN or a firewall. A custom resolver may have a wrong address.")
        case "bad_endpoint", "bootstrap_required", "bootstrap_failed":
            return ("The resolver is not usable", "server.rack", "Check the resolver's address, or pick another one.")
        case "malformed_response":
            return ("The answer did not parse", "doc.badge.ellipsis", "The server sent something that is not a valid DNS message.")
        case "trace_dead_end":
            return ("The trace hit a dead end", "point.topleft.down.to.point.bottomright.curvepath", "A server on the way down did not answer or did not know the zone. Zone check shows which.")
        default:
            return ("The run failed", "exclamationmark.triangle", nil)
        }
    }
}

/// Covers a tab's previous result while it re-runs. Appears after 150 ms so
/// fast queries do not flicker.
struct RunningOverlay: View {
    var name: String
    var mode: Mode
    var cancel: () -> Void
    @State private var visible = false

    var body: some View {
        ZStack {
            if visible {
                Rectangle().fill(Color(nsColor: .windowBackgroundColor).opacity(0.75))
                VStack(spacing: 12) {
                    ProgressView()
                    Text(verbatim: "\(mode == .health || mode == .email ? "Checking" : "Asking about") \(name)…")
                        .foregroundStyle(.secondary)
                    Button("Cancel", action: cancel).keyboardShortcut(.cancelAction)
                }
                .padding(24)
                .background(RoundedRectangle(cornerRadius: 12).fill(.regularMaterial))
            }
        }
        .task {
            try? await Task.sleep(for: .milliseconds(150))
            visible = true
        }
    }
}

/// The start panel: what the mode does in a sentence, then examples that
/// run on click. Left-aligned under the command bar, where the eye already
/// is; a centred paragraph in the middle of the window reads poorly.
struct Placeholder: View {
    @EnvironmentObject var model: AppModel
    var running: Bool
    var mode: Mode
    var body: some View {
        if running {
            VStack(spacing: 10) {
                ProgressView()
                Text("Asking the wire…").foregroundStyle(.secondary)
            }
        } else {
            VStack(alignment: .leading, spacing: 14) {
                Label(mode.title, systemImage: mode.icon)
                    .font(.title2.weight(.semibold))
                // Full width (the panel's 28 pt margins on both sides): it is one
                // or two sentences, so a reading-width cap only breaks it early.
                Text(mode.explanation)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(mode.prompt).font(.callout).foregroundStyle(.tertiary).padding(.top, 6)
                FlowLayout(spacing: 8) {
                    ForEach(mode.examples, id: \.self) { e in
                        Button { model.runExample(e) } label: {
                            HStack(spacing: 6) {
                                Text(e.name).font(.system(.callout, design: .monospaced))
                                if let t = e.type, t != "A" { Text(t).font(.caption.weight(.bold)).foregroundStyle(TypeStyle.ink(t)) }
                                if let n = e.note { Text(n).font(.caption).foregroundStyle(.secondary) }
                            }
                            .padding(.horizontal, 10).padding(.vertical, 5)
                            .background(Capsule().fill(Color.secondary.opacity(0.12)))
                            .contentShape(Capsule())
                        }
                        .buttonStyle(.plain)
                        .help("Run this example")
                    }
                }
            }
            .padding(.horizontal, 28).padding(.top, 28)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }
}

/// Lays children out in rows, wrapping to the next row when one is full.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(subviews, width: proposal.width ?? .infinity)
        let height = rows.map(\.height).reduce(0, +) + spacing * CGFloat(max(rows.count - 1, 0))
        let width = rows.map(\.width).max() ?? 0
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(subviews, width: bounds.width) {
            var x = bounds.minX
            for i in row.indices {
                let size = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row { var indices: [Int] = []; var width: CGFloat = 0; var height: CGFloat = 0 }

    private func arrange(_ subviews: Subviews, width: CGFloat) -> [Row] {
        var rows: [Row] = [Row()]
        for i in subviews.indices {
            let size = subviews[i].sizeThatFits(.unspecified)
            if !rows[rows.count - 1].indices.isEmpty, rows[rows.count - 1].width + spacing + size.width > width {
                rows.append(Row())
            }
            var r = rows[rows.count - 1]
            r.width += (r.indices.isEmpty ? 0 : spacing) + size.width
            r.height = max(r.height, size.height)
            r.indices.append(i)
            rows[rows.count - 1] = r
        }
        return rows
    }
}

/// Shared "Copy as…" items used by the toolbar and the menu bar.
struct ExportMenu: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        // Only the tools that can express this question (a trace is only
        // expressible as dig +trace).
        let formats = model.commandFormats
        ForEach(formats, id: \.self) { fmt in
            Button(model.mode == .trace ? "Copy as dig +trace" : "Copy as \(fmt)") {
                Task { if let cmd = await model.exportCommand(fmt) { Pasteboard.copy(cmd) } }
            }
            .disabled(model.trimmedName.isEmpty)
        }
        if !formats.isEmpty { Divider() }
        Button("Copy result as JSON") { if let s = model.exportJSON() { Pasteboard.copy(s) } }
            .disabled(model.outcome == nil)
        Button("Copy answers as Markdown table") { if let s = MarkdownExport.table(model.outcome) { Pasteboard.copy(s) } }
            .disabled(MarkdownExport.table(model.outcome) == nil)
        if case .health(let r) = model.outcome {
            Button("Copy health report as Markdown") { Pasteboard.copy(HealthReport.markdown(r)) }
        }
    }
}

enum MarkdownExport {
    static func table(_ outcome: Outcome?) -> String? {
        var rows: [Record] = []
        switch outcome {
        case .query(let rs): rows = rs.flatMap(\.message.answer)
        case .trace(let t): rows = t.final.answer
        case .compare(let c): rows = c.results.compactMap(\.message).flatMap(\.answer)
        case .email, .registry, .health: return nil
        case nil: return nil
        }
        var s = "| Name | TTL | Type | Data |\n|---|---:|---|---|\n"
        for r in rows {
            s += "| \(r.name) | \(r.ttl) | \(r.type) | \(r.rdata.replacingOccurrences(of: "|", with: "\\|")) |\n"
        }
        return s
    }
}
