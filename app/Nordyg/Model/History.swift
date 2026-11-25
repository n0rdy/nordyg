import Foundation

struct HistoryItem: Codable, Identifiable, Hashable {
    /// The `mode` of a Query that asked several resolvers. history.json
    /// holds this string, so it stays as it is.
    static let severalResolversMode = "compare"

    var id = UUID()
    var date = Date()
    var name: String
    var type: String
    var mode: String
    var endpoint: Endpoint?
    var pinned = false

    var askedSeveral: Bool { mode == Self.severalResolversMode }

    /// Whether the entry is listed under tab `m`.
    func belongs(to m: Mode) -> Bool { mode == m.rawValue || (m == .query && askedSeveral) }

    var subtitle: String {
        switch mode {
        case Self.severalResolversMode: return "several resolvers"
        case "trace": return "trace"
        default: return endpoint?.title ?? ""
        }
    }
}

/// The JSON lists the app keeps in its Application Support folder.
///
/// A list loads one entry at a time, so an entry that no longer decodes
/// (an older format, a hand edit) costs that entry and not the whole list.
/// A file that is not a list at all is moved aside as `<name>.unreadable.json`
/// before anything is saved over it.
enum SavedList {
    private struct Lossy<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: Decoder) throws { value = try? T(from: decoder) }
    }

    private static let directory: URL = {
        let dir = URL.applicationSupportDirectory.appendingPathComponent("Nordyg", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    static func file(_ name: String) -> URL { directory.appendingPathComponent(name) }

    static func load<T: Decodable>(_ url: URL) -> [T] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: url) else { return [] }
        if let items = try? decoder.decode([Lossy<T>].self, from: data) { return items.compactMap(\.value) }
        let aside = url.deletingPathExtension().appendingPathExtension("unreadable.json")
        try? FileManager.default.removeItem(at: aside)
        try? FileManager.default.moveItem(at: url, to: aside)
        return []
    }

    static func save<T: Encodable>(_ items: [T], to url: URL) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .prettyPrinted
        if let data = try? encoder.encode(items) { try? data.write(to: url, options: .atomic) }
    }
}

/// Resolvers the user added.
enum CustomResolverStore {
    private static let url = SavedList.file("resolvers.json")

    static func load() -> [Endpoint] { SavedList.load(url) }
    static func save(_ eps: [Endpoint]) { SavedList.save(eps, to: url) }
}

/// The query history, capped at 300 entries.
enum HistoryStore {
    static let limit = 300
    private static let url = SavedList.file("history.json")

    static func load() -> [HistoryItem] { SavedList.load(url) }
    static func save(_ items: [HistoryItem]) { SavedList.save(Array(items.prefix(limit)), to: url) }
}
