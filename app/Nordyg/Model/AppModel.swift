import Foundation
import SwiftUI

enum Mode: String, CaseIterable, Identifiable {
    case query, compare, trace, email, registry, health
    var id: String { rawValue }
    var title: String {
        switch self {
        case .query: return "Query"
        case .compare: return "Compare"
        case .trace: return "Trace"
        case .email: return "Email"
        case .registry: return "Registry"
        case .health: return "Zone check"
        }
    }
}

extension Mode {
    /// One line for the mode picker's tooltip.
    var summary: String {
        switch self {
        case .query: return "Ask one resolver and see everything it returned."
        case .compare: return "Ask several resolvers at once and see where they differ."
        case .trace: return "Follow the delegation from the root servers to the answer."
        case .email: return "Check a mail domain's MX, SPF, DKIM, DMARC, MTA-STS, BIMI and blocklists."
        case .registry: return "See who registered a domain, when it expires and its status, via RDAP or WHOIS."
        case .health: return "Check that a domain's DNS is delegated and served correctly."
        }
    }

    /// The fuller explanation shown before the mode has been run.
    var explanation: String {
        switch self {
        case .query:
            return "Ask one resolver and see everything it returned: flags, every section, EDNS options, timing, the raw message, and a DNSSEC chain that Nordyg checks itself. An IP address runs a reverse lookup. ALL asks for the common types at once."
        case .compare:
            return "Ask several resolvers the same question at once and see where their answers differ. Pick the resolvers from the token in the bar."
        case .trace:
            return "Follow the delegation from the root servers down to the server that holds the answer, one hop at a time, without any cache in the way."
        case .email:
            return "Check a mail domain: MX hosts and their reverse records, SPF and its lookup count, DKIM keys, the DMARC policy, MTA-STS, BIMI and blocklists, each with a verdict."
        case .registry:
            return "Look up who registered a domain, when it expires, its status codes, and the nameservers the registry has on file. Uses RDAP, and WHOIS for the TLDs that have no RDAP."
        case .health:
            return "Is this domain's DNS set up correctly? Nordyg finds what the parent zone delegates to, asks every nameserver directly, and compares their answers: serials, NS sets, glue, TCP, zone transfers, open recursion, DNSSEC and CAA."
        }
    }

    var icon: String {
        switch self {
        case .query: return "magnifyingglass"
        case .compare: return "square.split.2x1"
        case .trace: return "point.topleft.down.to.point.bottomright.curvepath"
        case .email: return "envelope"
        case .registry: return "building.columns"
        case .health: return "stethoscope"
        }
    }

    /// What to type, for the empty state's last line.
    var prompt: String {
        switch self {
        case .query, .compare, .trace: return "Type a name or an IP address and press ⌘↩."
        case .email: return "Type a mail domain and press ⌘↩."
        case .registry: return "Type a registered domain and press ⌘↩."
        case .health: return "Type a domain and press ⌘↩."
        }
    }

    /// Modes that take a domain rather than a name and record type.
    var takesDomain: Bool { self == .email || self == .registry || self == .health }
    /// Modes that ask through the selected resolver.
    var usesResolver: Bool { self == .query || takesDomain }
    /// The label history shows in place of a record type.
    var historyType: String? {
        switch self {
        case .email: return "MAIL"
        case .registry: return "RDAP"
        case .health: return "ZONE"
        default: return nil
        }
    }
}

enum Outcome {
    case query([QueryResult])
    case compare(CompareResult)
    case trace(TraceResult)
    case email(EmailResult)
    case registry(RDAPResult)
    case health(HealthResult)

    /// The mode that produced this outcome.
    var mode: Mode {
        switch self {
        case .query: return .query
        case .compare: return .compare
        case .trace: return .trace
        case .email: return .email
        case .registry: return .registry
        case .health: return .health
        }
    }
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
    @Published var dkimSelector = ""

    // Choices
    @Published var systemEndpoints: [Endpoint] = []
    @Published var presets: [Preset] = []
    @Published var customEndpoints: [Endpoint] = []
    @Published var coreVersion = ""

    // Outcome
    @Published var isRunning = false
    /// The last result of each mode, so tabs keep their own result.
    @Published var outcomes: [Mode: Outcome] = [:]
    /// The mode whose run is in flight, so only that tab shows progress.
    @Published var runningMode: Mode?
    /// The visible tab's result.
    var outcome: Outcome? { outcomes[mode] }
    @Published var resultVersion = 0

    // Watches
    let watches = WatchCenter()
    @Published var selectedWatch: UUID?

    // Cache visibility
    @Published var authoritative: [String: AuthoritativeAnswer] = [:]
    @Published var fetchingAuthoritative: Set<String> = []
    @Published var systemView: [String]?
    @Published var errorMessage: String?
    @Published var history: [HistoryItem] = HistoryStore.load()

    private var task: Task<Void, Never>?
    private let core = Core.shared

    init() {
        watches.bootstrap = { [weak self] in self?.bootstrap ?? [] }
    }

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
        case .query, .email, .registry, .health: return selected != nil
        case .compare: return !compareSelection.isEmpty
        case .trace: return true
        }
    }

    func run() {
        guard canRun else { return }
        let n = name.trimmingCharacters(in: .whitespaces)
        var t = type
        // Typing an IP address means a reverse lookup unless a type was chosen deliberately.
        if !mode.takesDomain, t == "A" || t == "ALL", isIPAddress(n) { t = "PTR"; type = "PTR" }
        let selector = dkimSelector.trimmingCharacters(in: .whitespaces)
        let question = Question(name: n, type: t, qclass: nil)
        let mode = self.mode
        let endpoint = selected
        let endpoints = allEndpoints.filter { compareSelection.contains($0) }
        let opts = options
        let validate = self.validate
        let boot = bootstrap

        errorMessage = nil
        isRunning = true
        runningMode = mode
        selectedWatch = nil
        systemView = nil
        if mode == .query, ["A", "AAAA", "ALL"].contains(t) {
            Task { [weak self] in
                let addrs = await SystemLookup.addresses(for: n)
                await MainActor.run { self?.systemView = addrs }
            }
        }
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
                case .email:
                    guard let endpoint else { return }
                    let r: EmailResult = try await self.core.call("email", EmailParams(domain: n, endpoint: endpoint, options: opts, bootstrap: boot, extraDkimSelectors: selector.isEmpty ? [] : [selector]))
                    out = .email(r)
                case .registry:
                    guard let endpoint else { return }
                    let r: RDAPResult = try await self.core.call("rdap", RDAPParams(domain: n, endpoint: endpoint, options: opts, bootstrap: boot))
                    out = .registry(r)
                case .health:
                    guard let endpoint else { return }
                    let r: HealthResult = try await self.core.call("health", HealthParams(domain: n, endpoint: endpoint, options: opts, bootstrap: boot))
                    out = .health(r)
                }
                self.outcomes[mode] = out
                self.resultVersion += 1
                self.remember(HistoryItem(name: n, type: mode.historyType ?? t, mode: mode.rawValue, endpoint: mode.usesResolver ? endpoint : nil))
            } catch is CancellationError {
                // user cancelled
            } catch let e as CoreError {
                if e.code != "cancelled" { self.errorMessage = e.message }
            } catch {
                self.errorMessage = error.localizedDescription
            }
            self.isRunning = false
            self.runningMode = nil
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

    /// Empties the visible tab, which shows its explanation again.
    func clearResult() {
        outcomes[mode] = nil
        errorMessage = nil
        resultVersion += 1
    }

    var canClear: Bool { outcome != nil && runningMode != mode }

    /// Start watching the current question at the selected resolver.
    func watchCurrent(interval: Int) {
        guard let ep = selected else { return }
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return }
        var t = type == "ALL" ? "A" : type
        if t == "A", isIPAddress(n) { t = "PTR" }
        let w = watches.add(question: Question(name: n, type: t, qclass: nil), endpoint: ep, interval: interval)
        selectedWatch = w.id
    }

    var canWatch: Bool { mode == .query && selected != nil && !name.trimmingCharacters(in: .whitespaces).isEmpty }

    // MARK: cache visibility

    static func authKey(_ q: Question) -> String {
        "\(q.name.lowercased().hasSuffix(".") ? q.name.lowercased() : q.name.lowercased() + ".")|\(q.type.uppercased())"
    }

    /// Fetches the authoritative answer with a silent trace, so cache age can
    /// be computed as authoritative TTL minus returned TTL.
    func fetchAuthoritative(for q: Question) {
        let key = Self.authKey(q)
        guard !fetchingAuthoritative.contains(key) else { return }
        fetchingAuthoritative.insert(key)
        Task { [weak self] in
            guard let self else { return }
            defer { self.fetchingAuthoritative.remove(key) }
            do {
                let r: TraceResult = try await self.core.call("trace", TraceParams(question: Question(name: q.name, type: q.type, qclass: nil), options: Options(timeoutMs: 4000), validate: false, bootstrap: [], rootHints: nil))
                var ttls: [String: Int] = [:]
                for rec in r.final.answer where rec.type.uppercased() == q.type.uppercased() { ttls[rec.rdata] = rec.ttl }
                self.authoritative[key] = AuthoritativeAnswer(ttls: ttls, rcode: r.final.rcode, fetched: Date(), server: r.hops.last?.server.name ?? "")
            } catch let e as CoreError {
                self.errorMessage = "Authoritative lookup failed: \(e.message)"
            } catch {}
        }
    }

    func cacheAge(of message: Message, question: Question) -> CacheAge {
        let key = Self.authKey(question)
        if fetchingAuthoritative.contains(key) { return .checking }
        guard let auth = authoritative[key] else { return .unknown }
        let answers = message.answer.filter { $0.type.uppercased() == question.type.uppercased() }
        if answers.isEmpty { return auth.ttls.isEmpty ? .fresh : .differs }
        var ages: [Int] = []
        for a in answers {
            if let t = auth.ttls[a.rdata] { ages.append(t - a.ttl) }
        }
        if ages.isEmpty { return .differs }
        let age = ages.max() ?? 0
        if age < -1 { return .differs }
        return age <= 2 ? .fresh : .cached(age)
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
        if !Mode.allCases.contains(where: { $0.historyType == item.type }) { type = item.type }
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
        case .email(let r): data = try? enc.encode(r)
        case .registry(let r): data = try? enc.encode(r)
        case .health(let r): data = try? enc.encode(r)
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

struct AuthoritativeAnswer {
    var ttls: [String: Int]   // rdata → TTL as published by the authoritative server
    var rcode: String
    var fetched: Date
    var server: String
}

enum CacheAge: Equatable {
    case unknown, checking, fresh, cached(Int), differs
}
