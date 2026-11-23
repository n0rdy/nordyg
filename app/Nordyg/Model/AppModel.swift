import Combine
import Foundation
import SwiftUI

enum Mode: String, CaseIterable, Identifiable {
    case query, trace, email, registry, health
    var id: String { rawValue }
    var title: String {
        switch self {
        case .query: return "Query"
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
        case .query: return "Ask one resolver, or several at once, and see everything they returned."
        case .trace: return "Follow the delegation from the root servers to the answer."
        case .email: return "Check a mail domain's MX, SPF, DKIM, DMARC, MTA-STS, DANE, BIMI and blocklists."
        case .registry: return "See who registered a domain, when it expires and its status, via RDAP or WHOIS."
        case .health: return "Check that a domain's DNS is delegated and served correctly, and its website certificate."
        }
    }

    /// One or two sentences for the start panel shown before the mode runs.
    var explanation: String {
        switch self {
        case .query:
            return "Ask a resolver what it has for a name and see everything it sent back, with a DNSSEC check Nordyg does itself.\nPick “Several resolvers…” in the resolver menu to compare them."
        case .trace:
            return "Follow a name from the root servers down to the server that holds the answer, one hop at a time, with no cache in the way."
        case .email:
            return "Check whether a domain's mail is set up right: MX, SPF, DKIM, DMARC, MTA-STS, DANE, BIMI and blocklists, each with a verdict."
        case .registry:
            return "See who registered a domain, when it expires and its status, from RDAP, or from WHOIS where a TLD has no RDAP."
        case .health:
            return "Check that a domain's DNS is delegated and served correctly, by asking every one of its nameservers directly, and that the certificate its website serves is valid."
        }
    }

    /// Clickable examples for the start panel: each shows a feature by doing it.
    var examples: [ModeExample] {
        switch self {
        case .query:
            return [
                ModeExample(name: "cloudflare.com", type: "A"),
                ModeExample(name: "1.1.1.1", type: "A", note: "reverse lookup"),
                ModeExample(name: "dnssec-failed.org", type: "A", note: "broken DNSSEC"),
                ModeExample(name: "cloudflare.com", type: "ALL", note: "every common type"),
                ModeExample(name: "cloudflare.com", type: "A", note: "several resolvers", several: true),
            ]
        case .trace:
            return [
                ModeExample(name: "cloudflare.com", type: "A"),
                ModeExample(name: "dnssec-failed.org", type: "A", note: "broken DNSSEC"),
            ]
        case .email:
            return [ModeExample(name: "cloudflare.com"), ModeExample(name: "proton.me")]
        case .registry:
            return [ModeExample(name: "cloudflare.com"), ModeExample(name: "about.me", note: "WHOIS, .me has no RDAP")]
        case .health:
            return [ModeExample(name: "cloudflare.com"), ModeExample(name: "dnssec-failed.org", note: "broken DNSSEC")]
        }
    }

    var icon: String {
        switch self {
        case .query: return "magnifyingglass"
        case .trace: return "point.topleft.down.to.point.bottomright.curvepath"
        case .email: return "envelope"
        case .registry: return "building.columns"
        case .health: return "stethoscope"
        }
    }

    /// What to type, for the start panel.
    var prompt: String {
        switch self {
        case .query, .trace: return "Type a name or an IP address and press ⌘↩, or try"
        case .email: return "Type a mail domain and press ⌘↩, or try"
        case .registry: return "Type a registered domain and press ⌘↩, or try"
        case .health: return "Type a domain and press ⌘↩, or try"
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
        case .compare: return .query
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
    /// Query asks every resolver in `compareSelection` instead of `selected`
    /// and shows the comparison grid (what used to be the Compare mode).
    @Published var severalResolvers = false {
        didSet { if severalResolvers, type == "ALL" { type = "A" } }
    }
    /// This Mac's resolver configuration, kept live.
    let macDNS = MacDNSMonitor()
    /// "How this Mac resolves names" is open.
    @Published var showMacResolvers = false
    /// The several-resolvers checklist popover is open.
    @Published var showResolverChecklist = false
    /// The compared resolver whose full answer is open (index into results).
    @Published var compareDetail: Int?
    @Published var validate = true
    @Published var options = Options()
    @Published var dkimSelector = ""

    // Choices
    @Published var systemEndpoints: [Endpoint] = []
    @Published var presets: [Preset] = []
    @Published var customEndpoints: [Endpoint] = CustomResolverStore.load()
    @Published var coreVersion = ""

    // Outcome
    @Published var isRunning = false
    /// The last result of each mode, so tabs keep their own result.
    @Published var outcomes: [Mode: Outcome] = [:]
    /// The failed run of each mode, shown in place of its result.
    @Published var runErrors: [Mode: CoreError] = [:]
    /// The mode whose run is in flight, so only that tab shows progress.
    @Published var runningMode: Mode?
    /// The name being asked about, for the progress overlay.
    @Published var runningName = ""
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
    /// The name `systemView` was looked up for, so it is only ever compared
    /// with an answer for that same name.
    @Published var systemViewName = ""
    @Published var errorMessage: String?
    @Published var history: [HistoryItem] = HistoryStore.load()
    /// The result tab chosen in each mode (Records/Details/…), kept across runs
    /// so re-running a query stays on the tab being looked at.
    @Published var resultTabs: [Mode: String] = [:]
    /// Sidebar shows only this mode's history; nil shows all.
    @Published var historyFilter: Mode?

    private var task: Task<Void, Never>?
    private let core = Core.shared

    private var watchChanges: AnyCancellable?

    init() {
        watches.bootstrap = { [weak self] in self?.bootstrap ?? [] }
        // The scene (menu bar icon, toolbar) observes the model; pass watch
        // changes through so they re-render too.
        watchChanges = watches.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }
    }

    /// Every endpoint the picker offers, in display order.
    var allEndpoints: [Endpoint] {
        systemEndpoints + resolvedPresets.flatMap { p in p.endpoints.filter { !$0.needsPlaceholder } } + customEndpoints
    }

    /// Presets as one entry per provider, for the compact resolver pickers.
    var providers: [Provider] {
        resolvedPresets.compactMap { p in
            let usable = p.endpoints.filter { !$0.needsPlaceholder }
            return usable.isEmpty ? nil : Provider(name: p.name, all: usable, presetID: p.id, requires: p.requires ?? [])
        }
    }

    /// Values for preset placeholders (NextDNS's profile_id), kept in settings.
    @Published var presetValues: [String: String] = UserDefaults.standard.dictionary(forKey: "presetValues") as? [String: String] ?? [:] {
        didSet { UserDefaults.standard.set(presetValues, forKey: "presetValues") }
    }
    /// The preset whose setup sheet is open.
    @Published var setupPreset: String?

    /// Presets with their placeholders filled from `presetValues`.
    var resolvedPresets: [Preset] {
        presets.map { p in
            guard let req = p.requires, !req.isEmpty else { return p }
            var q = p
            q.endpoints = p.endpoints.map { ep in
                var e = ep
                for k in req {
                    guard let v = presetValues[k], !v.isEmpty else { continue }
                    e.url = e.url?.replacingOccurrences(of: "{\(k)}", with: v)
                    e.tlsName = e.tlsName?.replacingOccurrences(of: "{\(k)}", with: v)
                }
                return e
            }
            return q
        }
    }

    /// Presets that cannot be used until a value is entered.
    var presetsNeedingSetup: [Preset] {
        resolvedPresets.filter { !$0.endpoints.isEmpty && $0.endpoints.allSatisfy(\.needsPlaceholder) }
    }

    /// Saves a preset's values and switches to its first endpoint.
    func configurePreset(_ id: String, values: [String: String]) {
        for (k, v) in values { presetValues[k] = v }
        if let p = resolvedPresets.first(where: { $0.id == id }), let ep = Provider(name: p.name, all: p.endpoints.filter { !$0.needsPlaceholder }).primary.first(where: { $0.transport == "dot" }) ?? p.endpoints.first(where: { !$0.needsPlaceholder }) {
            selected = ep
        }
    }

    func clearPreset(_ id: String) {
        guard let p = presets.first(where: { $0.id == id }) else { return }
        let had = allEndpoints
        for k in p.requires ?? [] { presetValues[k] = nil }
        if let s = selected, had.contains(s), !allEndpoints.contains(s) { selected = systemEndpoints.first }
        compareSelection = compareSelection.filter { allEndpoints.contains($0) }
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
        case .query: return severalResolvers ? !compareSelection.isEmpty : selected != nil
        case .email, .registry, .health: return selected != nil
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
        let several = mode == .query && severalResolvers
        let endpoint = selected
        let endpoints = allEndpoints.filter { compareSelection.contains($0) }
        let opts = options
        let validate = self.validate
        let boot = bootstrap

        errorMessage = nil
        runErrors[mode] = nil
        isRunning = true
        runningMode = mode
        runningName = n
        selectedWatch = nil
        systemView = nil
        compareDetail = nil
        if mode == .query, !several, ["A", "AAAA", "ALL"].contains(t) {
            Task { [weak self] in
                let addrs = await SystemLookup.addresses(for: n)
                await MainActor.run { self?.systemView = addrs; self?.systemViewName = n }
            }
        }
        task = Task { [weak self] in
            guard let self else { return }
            do {
                let out: Outcome
                switch mode {
                case .query where several:
                    let r: CompareResult = try await self.core.call("compare", CompareParams(question: question, endpoints: endpoints, options: opts, bootstrap: boot))
                    out = .compare(r)
                case .query:
                    guard let endpoint else { return }
                    if t == "ALL" {
                        out = .query(try await self.fanOut(question, endpoint, opts, validate, boot))
                    } else {
                        let r: QueryResult = try await self.core.call("query", QueryParams(question: question, endpoint: endpoint, options: opts, validate: validate, bootstrap: boot))
                        out = .query([r])
                    }
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
                // Several-resolver runs keep the history mode "compare" (what
                // they were called before), so re-running restores them.
                self.remember(HistoryItem(name: n, type: mode.historyType ?? t, mode: several ? "compare" : mode.rawValue, endpoint: mode.usesResolver && !several ? endpoint : nil))
            } catch is CancellationError {
                // user cancelled
            } catch let e as CoreError {
                // A failed run replaces the tab's result: an old answer next to
                // a new error reads as if it belonged to the new input.
                if e.code != "cancelled" { self.failRun(mode, e) }
            } catch {
                self.failRun(mode, CoreError(code: "internal", message: error.localizedDescription, details: nil))
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

    private func failRun(_ mode: Mode, _ e: CoreError) {
        outcomes[mode] = nil
        runErrors[mode] = e
        resultVersion += 1
    }

    /// From a one-resolver answer: ask the same question of several
    /// resolvers, the one just used among them.
    func askOtherResolvers(including ep: Endpoint) {
        if let known = allEndpoints.first(where: { $0 == ep }) ?? selected { compareSelection.insert(known) }
        severalResolvers = true
        run()
    }

    /// Runs a start-panel example in the current mode.
    func runExample(_ e: ModeExample) {
        name = e.name
        if let t = e.type { type = t }
        if mode == .query { severalResolvers = e.several }
        run()
    }

    /// Empties the visible tab, which shows its explanation again.
    func clearResult() {
        outcomes[mode] = nil
        runErrors[mode] = nil
        errorMessage = nil
        resultVersion += 1
    }

    var canClear: Bool { (outcome != nil || runErrors[mode] != nil) && runningMode != mode }

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

    var canWatch: Bool { mode == .query && !severalResolvers && selected != nil && !name.trimmingCharacters(in: .whitespaces).isEmpty }

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
        if item.mode == "compare" {
            mode = .query
            severalResolvers = true
        } else {
            mode = Mode(rawValue: item.mode) ?? .query
            if mode == .query { severalResolvers = false }
        }
        if let ep = item.endpoint { selected = ep }
        run()
    }

    // MARK: export

    func exportCommand(_ format: String) async -> String? {
        // Several resolvers export one command each, in picker order. Trace
        // asks no resolver; the endpoint is a placeholder the core ignores.
        let placeholder = Endpoint(transport: "udp", address: "127.0.0.1:53", tlsName: nil, url: nil, method: nil, label: nil)
        let endpoints = mode == .trace ? [placeholder] : (mode == .query && severalResolvers ? allEndpoints.filter { compareSelection.contains($0) } : (selected.map { [$0] } ?? []))
        guard !endpoints.isEmpty else { return nil }
        let n = name.trimmingCharacters(in: .whitespaces)
        // ALL is Nordyg's own fan-out; no CLI tool has it (ANY is deprecated,
        // RFC 8482), so it exports as one command per type it actually asks.
        let types = type == "ALL" ? RecordTypes.fanOut : [type]
        do {
            var lines: [String] = []
            for ep in endpoints {
                for t in types {
                    let r: ExportResult = try await core.call("export", ExportParams(question: Question(name: n, type: t, qclass: nil), endpoint: ep, options: options, format: format, trace: mode == .trace))
                    lines.append(r.command)
                }
            }
            return lines.joined(separator: "\n")
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
        CustomResolverStore.save(customEndpoints)
        selected = ep
    }

    func removeCustom(_ ep: Endpoint) {
        customEndpoints.removeAll { $0.id == ep.id }
        compareSelection.remove(ep)
        CustomResolverStore.save(customEndpoints)
        if selected == ep { selected = systemEndpoints.first ?? allEndpoints.first }
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

/// One resolver operator and every address it publishes. Pickers show the
/// provider once, with its transports; the IPv6 and secondary addresses sit
/// behind "More addresses", since most people mean "ask Cloudflare".
struct Provider: Identifiable {
    var name: String
    var all: [Endpoint]
    var presetID: String = ""
    var requires: [String] = []
    var id: String { name }

    static let transportOrder = ["udp", "tcp", "dot", "doh", "doq"]

    /// One endpoint per transport: the first IPv4, non-secondary address.
    var primary: [Endpoint] {
        Provider.transportOrder.compactMap { t in
            let ofT = all.filter { $0.transport == t }
            return ofT.first { $0.isIPv4 && !$0.isSecondary } ?? ofT.first
        }
    }
}

extension Endpoint {
    var isIPv4: Bool { !(address ?? "").contains("[") && !(address ?? "").contains("::") }
    var isSecondary: Bool { (label ?? "").lowercased().contains("secondary") }
}

/// A start-panel example: what goes in the bar, and why it is interesting.
struct ModeExample: Hashable {
    var name: String
    var type: String?
    var note: String?
    var several = false
}
