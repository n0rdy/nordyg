import Foundation

struct HistoryItem: Codable, Identifiable, Hashable {
    var id = UUID()
    var date = Date()
    var name: String
    var type: String
    var mode: String
    var endpoint: Endpoint?
    var pinned = false

    var subtitle: String {
        switch mode {
        case "compare": return "several resolvers"
        case "trace": return "trace"
        default: return endpoint?.title ?? ""
        }
    }
}

/// Resolvers the user added, saved next to the history.
enum CustomResolverStore {
    static var url: URL { HistoryStore.url.deletingLastPathComponent().appendingPathComponent("resolvers.json") }

    static func load() -> [Endpoint] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([Endpoint].self, from: data)) ?? []
    }

    static func save(_ eps: [Endpoint]) {
        let e = JSONEncoder()
        e.outputFormatting = .prettyPrinted
        if let data = try? e.encode(eps) { try? data.write(to: url, options: .atomic) }
    }
}

/// JSON file in the sandbox's Application Support, capped at 300 entries.
enum HistoryStore {
    static let limit = 300

    static var url: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = base.appendingPathComponent("Nordyg", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("history.json")
    }

    static func load() -> [HistoryItem] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return (try? d.decode([HistoryItem].self, from: data)) ?? []
    }

    static func save(_ items: [HistoryItem]) {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = .prettyPrinted
        if let data = try? e.encode(Array(items.prefix(limit))) {
            try? data.write(to: url, options: .atomic)
        }
    }
}
