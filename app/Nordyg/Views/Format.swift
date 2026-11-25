import AppKit
import SwiftUI

func ms(_ v: Double) -> String { v < 10 ? String(format: "%.1f ms", v) : String(format: "%.0f ms", v) }

/// A count with its noun: "1 hop", "3 hops", "2 addresses".
func plural(_ n: Int, _ one: String, _ many: String? = nil) -> String { "\(n) \(n == 1 ? one : (many ?? one + "s"))" }

/// Names for prose: no trailing dot, and TLDs written as ".me" so they do
/// not read like words.
func prose(_ name: String) -> String {
    name == "." ? "the root" : name.withoutTrailingDot
}

func proseZone(_ zone: String) -> String {
    let bare = zone.withoutTrailingDot
    if bare.isEmpty { return "the root zone" }
    return bare.contains(".") ? "the zone \(bare)" : "the .\(bare) zone"
}

extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
    var withoutTrailingDot: String { hasSuffix(".") ? String(dropLast()) : self }
}

/// The core's RFC 3339 timestamps, with or without fractional seconds.
enum ISODate {
    private static let plain = ISO8601DateFormatter()
    private static let fractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    static func parse(_ s: String) -> Date? { fractional.date(from: s) ?? plain.date(from: s) }
}

enum Pasteboard {
    static func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}
