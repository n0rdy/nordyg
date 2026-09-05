import Foundation
import SwiftUI
import UserNotifications

struct WatchEvent: Codable, Identifiable, Hashable {
    var id = UUID()
    var date: Date
    var rcode: String
    var answers: [String]      // sorted "TYPE rdata"
    var changed: Bool
    var error: String?
}

struct Watch: Codable, Identifiable, Hashable {
    var id = UUID()
    var question: Question
    var endpoint: Endpoint
    var intervalSeconds: Int
    var created = Date()
    var paused = false
    var unread = false            // a change happened since the watch was last viewed
    var events: [WatchEvent] = []

    var title: String { "\(question.name) \(question.type)" }
    var last: WatchEvent? { events.first }
    var changes: Int { events.filter(\.changed).count }
    var intervalLabel: String { WatchCenter.intervalLabel(intervalSeconds) }
}

/// Re-runs queries on an interval, records changes, notifies, persists.
/// Pure shell logic over the existing `query` op, as the bridge rules require.
@MainActor
final class WatchCenter: ObservableObject {
    @Published private(set) var watches: [Watch] = []
    private var loops: [UUID: Task<Void, Never>] = [:]
    private let core = Core.shared
    var bootstrap: () -> [Endpoint] = { [] }

    nonisolated static let intervals = [30, 60, 300, 900, 3600]
    static let maxEvents = 200

    nonisolated static func intervalLabel(_ s: Int) -> String {
        switch s {
        case ..<60: return "\(s) s"
        case ..<3600: return "\(s / 60) min"
        default: return "\(s / 3600) h"
        }
    }

    init() {
        watches = WatchStore.load()
        for w in watches where !w.paused { start(w.id) }
    }

    var anyUnread: Bool { watches.contains(where: \.unread) }

    // MARK: lifecycle

    func add(question: Question, endpoint: Endpoint, interval: Int) -> Watch {
        let w = Watch(question: question, endpoint: endpoint, intervalSeconds: interval)
        watches.insert(w, at: 0)
        save()
        requestNotificationPermission()
        start(w.id)
        return w
    }

    func remove(_ id: UUID) {
        loops[id]?.cancel()
        loops[id] = nil
        watches.removeAll { $0.id == id }
        save()
    }

    func setPaused(_ id: UUID, _ paused: Bool) {
        guard let i = index(id) else { return }
        watches[i].paused = paused
        save()
        if paused { loops[id]?.cancel(); loops[id] = nil } else { start(id) }
    }

    func setInterval(_ id: UUID, _ seconds: Int) {
        guard let i = index(id) else { return }
        watches[i].intervalSeconds = seconds
        save()
        if !watches[i].paused { start(id) }
    }

    func markRead(_ id: UUID) {
        guard let i = index(id), watches[i].unread else { return }
        watches[i].unread = false
        save()
    }

    func checkNow(_ id: UUID) {
        Task { await check(id) }
    }

    private func index(_ id: UUID) -> Int? { watches.firstIndex { $0.id == id } }

    private func start(_ id: UUID) {
        loops[id]?.cancel()
        loops[id] = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, let w = self.watches.first(where: { $0.id == id }) else { return }
                await self.check(id)
                try? await Task.sleep(nanoseconds: UInt64(w.intervalSeconds) * 1_000_000_000)
            }
        }
    }

    // MARK: checking

    private func check(_ id: UUID) async {
        guard let w = watches.first(where: { $0.id == id }) else { return }
        var event = WatchEvent(date: Date(), rcode: "", answers: [], changed: false)
        do {
            let r: QueryResult = try await core.call("query", QueryParams(question: w.question, endpoint: w.endpoint, options: Options(timeoutMs: 5000), validate: false, bootstrap: bootstrap()))
            event.rcode = r.message.rcode
            event.answers = r.message.answer.map { "\($0.type) \($0.rdata)" }.sorted()
        } catch let e as CoreError {
            event.error = e.message
        } catch {
            event.error = error.localizedDescription
        }
        guard let i = index(id) else { return }
        let previous = watches[i].events.first { $0.error == nil }
        if let p = previous, event.error == nil {
            event.changed = p.rcode != event.rcode || p.answers != event.answers
        }
        watches[i].events.insert(event, at: 0)
        if watches[i].events.count > Self.maxEvents { watches[i].events.removeLast(watches[i].events.count - Self.maxEvents) }
        if event.changed {
            watches[i].unread = true
            notify(watches[i], from: previous, to: event)
        }
        save()
    }

    // MARK: notifications

    private var askedPermission = false

    private func requestNotificationPermission() {
        guard !askedPermission else { return }
        askedPermission = true
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private func notify(_ w: Watch, from: WatchEvent?, to: WatchEvent) {
        let content = UNMutableNotificationContent()
        content.title = "\(w.title) changed"
        let was = from.map { $0.answers.isEmpty ? $0.rcode : $0.answers.joined(separator: ", ") } ?? "—"
        let now = to.answers.isEmpty ? to.rcode : to.answers.joined(separator: ", ")
        content.body = "Was: \(was)\nNow: \(now)\nvia \(w.endpoint.title)"
        content.sound = .default
        let req = UNNotificationRequest(identifier: "watch-\(w.id)-\(to.id)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }

    private func save() { WatchStore.save(watches) }
}

enum WatchStore {
    static var url: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = base.appendingPathComponent("Nordyg", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("watches.json")
    }

    static func load() -> [Watch] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return (try? d.decode([Watch].self, from: data)) ?? []
    }

    static func save(_ items: [Watch]) {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        if let data = try? e.encode(items) { try? data.write(to: url, options: .atomic) }
    }
}
