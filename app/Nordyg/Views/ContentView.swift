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
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    ExportMenu()
                } label: {
                    Label("Copy as", systemImage: "doc.on.doc")
                }
                .disabled(model.outcome == nil && model.name.isEmpty)
            }
        }
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
            switch model.outcome {
            case .none:
                Placeholder(running: model.isRunning)
            case .query(let results):
                QueryResultView(results: results)
            case .compare(let r):
                CompareView(result: r)
            case .trace(let r):
                TraceView(result: r)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct Placeholder: View {
    var running: Bool
    var body: some View {
        VStack(spacing: 10) {
            if running {
                ProgressView()
                Text("Querying…").foregroundStyle(.secondary)
            } else {
                Image(systemName: "network").font(.system(size: 40)).foregroundStyle(.tertiary)
                Text("Type a name, pick a type and a resolver, press ⌘↩").foregroundStyle(.secondary)
            }
        }
    }
}

/// Shared "Copy as…" items used by the toolbar and the menu bar.
struct ExportMenu: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        ForEach(["dig", "nslookup", "doggo", "curl"], id: \.self) { fmt in
            Button("Copy as \(fmt)") {
                Task { if let cmd = await model.exportCommand(fmt) { Pasteboard.copy(cmd) } }
            }
        }
        Divider()
        Button("Copy result as JSON") { if let s = model.exportJSON() { Pasteboard.copy(s) } }
            .disabled(model.outcome == nil)
        Button("Copy answers as Markdown table") { if let s = MarkdownExport.table(model.outcome) { Pasteboard.copy(s) } }
            .disabled(model.outcome == nil)
    }
}

enum Pasteboard {
    static func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}

enum MarkdownExport {
    static func table(_ outcome: Outcome?) -> String? {
        var rows: [Record] = []
        switch outcome {
        case .query(let rs): rows = rs.flatMap(\.message.answer)
        case .trace(let t): rows = t.final.answer
        case .compare(let c): rows = c.results.compactMap(\.message).flatMap(\.answer)
        case nil: return nil
        }
        var s = "| Name | TTL | Type | Data |\n|---|---:|---|---|\n"
        for r in rows {
            s += "| \(r.name) | \(r.ttl) | \(r.type) | \(r.rdata.replacingOccurrences(of: "|", with: "\\|")) |\n"
        }
        return s
    }
}
