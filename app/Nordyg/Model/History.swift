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

/// Loads a saved list one entry at a time, so an entry that no longer decodes
/// (an older format, a hand edit) costs that entry and not the whole list.
/// A file that is not a list at all is moved aside as `<name>.unreadable.json`
/// before anything is saved over it.
enum SavedList {
    private struct Lossy<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: Decoder) throws { value = try? T(from: decoder) }
    }

    static func load<T: Decodable>(_ url: URL, decoder: JSONDecoder = JSONDecoder()) -> [T] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        if let items = try? decoder.decode([Lossy<T>].self, from: data) { return items.compactMap(\.value) }
        let aside = url.deletingPathExtension().appendingPathExtension("unreadable.json")
        try? FileManager.default.removeItem(at: aside)
        try? FileManager.default.moveItem(at: url, to: aside)
        return []
    }
}

/// Resolvers the user added, saved next to the history.
enum CustomResolverStore {
    static var url: URL { HistoryStore.url.deletingLastPathComponent().appendingPathComponent("resolvers.json") }

    static func load() -> [Endpoint] {
        SavedList.load(url)
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
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return SavedList.load(url, decoder: d)
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
