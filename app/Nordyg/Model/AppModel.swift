import Foundation
import SwiftUI

enum Mode: String, CaseIterable, Identifiable {
    case query, compare, trace
    var id: String { rawValue }
    var title: String {
        switch self {
        case .query: return "Query"
        case .compare: return "Compare"
        case .trace: return "Trace"
        }
    }
}

enum Outcome {
    case query([QueryResult])
    case compare(CompareResult)
    case trace(TraceResult)
}

@MainActor
final class AppModel: ObservableObject {
    // Form
    @Published var name = ""
    @Published var type = "A"
    @Published var mode: Mode = .query
    @Published var selected: Endpoint?
    @Published var compareSelection: Set<Endpoint> = []
    @Published var validate = true
    @Published var options = Options()

    // Choices
    @Published var systemEndpoints: [Endpoint] = []
    @Published var presets: [Preset] = []
    @Published var customEndpoints: [Endpoint] = []
    @Published var coreVersion = ""

    // Outcome
    @Published var isRunning = false
    @Published var outcome: Outcome?
    @Published var resultVersion = 0
    @Published var selectedRecord: Record?
    @Published var showInspector = false
    @Published var errorMessage: String?
    @Published var history: [HistoryItem] = HistoryStore.load()

    private var task: Task<Void, Never>?
    private let core = Core.shared

    /// Every endpoint the picker offers, in display order.
    var allEndpoints: [Endpoint] {
        systemEndpoints + presets.flatMap { p in p.endpoints.filter { !$0.needsPlaceholder } } + customEndpoints
    }

    /// Bootstrap resolvers for DoH: the system ones, plain UDP.
    var bootstrap: [Endpoint] { systemEndpoints }

    func load() async {
        systemEndpoints = SystemResolvers.endpoints()
        do {
            let ping: PingResult = try await core.call("ping")
            coreVersion = ping.version
            let p: PresetsResult = try await core.call("presets")
            presets = p.presets
        } catch {
            errorMessage = "Core failed to start: \(error.localizedDescription)"
        }
        if selected == nil {
            selected = systemEndpoints.first ?? allEndpoints.first
        }
        if compareSelection.isEmpty {
            for p in presets.prefix(3) {
                if let ep = p.endpoints.first(where: { $0.transport == "udp" && !($0.address ?? "").contains("[") }) {
                    compareSelection.insert(ep)
                }
            }
            if let s = systemEndpoints.first { compareSelection.insert(s) }
        }
    }

    // MARK: running

    var canRun: Bool {
        let n = name.trimmingCharacters(in: .whitespaces)
        if n.isEmpty || isRunning { return false }
        switch mode {
        case .query: return selected != nil
        case .compare: return !compareSelection.isEmpty
        case .trace: return true
        }
    }

    func run() {
        guard canRun else { return }
        let n = name.trimmingCharacters(in: .whitespaces)
        var t = type
        // Typing an IP address means a reverse lookup unless a type was chosen deliberately.
        if t == "A" || t == "ALL", isIPAddress(n) { t = "PTR"; type = "PTR" }
        let question = Question(name: n, type: t, qclass: nil)
        let mode = self.mode
        let endpoint = selected
        let endpoints = allEndpoints.filter { compareSelection.contains($0) }
        let opts = options
        let validate = self.validate
        let boot = bootstrap

        errorMessage = nil
        isRunning = true
        task = Task { [weak self] in
            guard let self else { return }
            do {
                let out: Outcome
                switch mode {
                case .query:
                    guard let endpoint else { return }
                    if t == "ALL" {
                        out = .query(try await self.fanOut(question, endpoint, opts, validate, boot))
                    } else {
                        let r: QueryResult = try await self.core.call("query", QueryParams(question: question, endpoint: endpoint, options: opts, validate: validate, bootstrap: boot))
                        out = .query([r])
                    }
                case .compare:
                    let r: CompareResult = try await self.core.call("compare", CompareParams(question: question, endpoints: endpoints, options: opts, bootstrap: boot))
                    out = .compare(r)
                case .trace:
                    let r: TraceResult = try await self.core.call("trace", TraceParams(question: question, options: opts, validate: validate, bootstrap: boot, rootHints: nil))
                    out = .trace(r)
                }
                self.outcome = out
                self.resultVersion += 1
                self.selectedRecord = nil
                self.remember(HistoryItem(name: n, type: t, mode: mode.rawValue, endpoint: mode == .query ? endpoint : nil))
            } catch is CancellationError {
                // user cancelled
            } catch let e as CoreError {
                if e.code != "cancelled" { self.errorMessage = e.message }
            } catch {
                self.errorMessage = error.localizedDescription
            }
            self.isRunning = false
        }
    }

    private func fanOut(_ q: Question, _ ep: Endpoint, _ o: Options, _ validate: Bool, _ boot: [Endpoint]) async throws -> [QueryResult] {
        try await withThrowingTaskGroup(of: (Int, QueryResult).self) { group in
            for (i, t) in RecordTypes.fanOut.enumerated() {
                group.addTask {
                    let r: QueryResult = try await self.core.call("query", QueryParams(question: Question(name: q.name, type: t, qclass: nil), endpoint: ep, options: o, validate: validate, bootstrap: boot))
                    return (i, r)
                }
            }
            var results: [(Int, QueryResult)] = []
            for try await r in group { results.append(r) }
            return results.sorted { $0.0 < $1.0 }.map(\.1)
        }
    }

    func cancel() {
        task?.cancel()
    }

    /// Fill the form from a record target and run again (the "click an MX
    /// target to resolve inline" action).
    func resolve(_ target: String, type: String = "A") {
        name = target.hasSuffix(".") ? String(target.dropLast()) : target
        self.type = type
        mode = .query
        run()
    }

    func rerun(_ item: HistoryItem) {
        name = item.name
        type = item.type
        mode = Mode(rawValue: item.mode) ?? .query
        if let ep = item.endpoint { selected = ep }
        run()
    }

    // MARK: export

    func exportCommand(_ format: String) async -> String? {
        guard let ep = selected else { return nil }
        let q = Question(name: name.trimmingCharacters(in: .whitespaces), type: type == "ALL" ? "A" : type, qclass: nil)
        do {
            let r: ExportResult = try await core.call("export", ExportParams(question: q, endpoint: ep, options: options, format: format))
            return r.command
        } catch let e as CoreError {
            errorMessage = e.message
            return nil
        } catch {
            errorMessage = error.localizedDescription
            return nil
        }
    }

    func exportJSON() -> String? {
        let enc = JSONEncoder()
        enc.keyEncodingStrategy = .convertToSnakeCase
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data?
        switch outcome {
        case .query(let r): data = r.count == 1 ? try? enc.encode(r[0]) : try? enc.encode(r)
        case .compare(let r): data = try? enc.encode(r)
        case .trace(let r): data = try? enc.encode(r)
        case nil: data = nil
        }
        return data.flatMap { String(data: $0, encoding: .utf8) }
    }

    // MARK: history

    private func remember(_ item: HistoryItem) {
        history.removeAll { $0.name == item.name && $0.type == item.type && $0.mode == item.mode && $0.endpoint == item.endpoint && !$0.pinned }
        history.insert(item, at: 0)
        HistoryStore.save(history)
    }

    func togglePin(_ item: HistoryItem) {
        if let i = history.firstIndex(of: item) { history[i].pinned.toggle(); HistoryStore.save(history) }
    }

    func delete(_ item: HistoryItem) {
        history.removeAll { $0 == item }
        HistoryStore.save(history)
    }

    func clearHistory() {
        history.removeAll { !$0.pinned }
        HistoryStore.save(history)
    }

    func addCustom(_ ep: Endpoint) {
        customEndpoints.removeAll { $0.id == ep.id }
        customEndpoints.append(ep)
        selected = ep
    }
}

func isIPAddress(_ s: String) -> Bool {
    var v4 = in_addr(); var v6 = in6_addr()
    return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1
}
