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
            return
                "Ask a resolver what it has for a name and see everything it sent back, with a DNSSEC check Nordyg does itself.\nPick “Several resolvers…” in the resolver menu to compare them."
        case .trace:
            return
                "Follow a name from the root servers down to the server that holds the answer, one hop at a time, with no cache in the way."
        case .email:
            return
                "Check whether a domain's mail is set up right: MX, SPF, DKIM, DMARC, MTA-STS, DANE, BIMI and blocklists, each with a verdict."
        case .registry:
            return "See who registered a domain, when it expires and its status, from RDAP, or from WHOIS where a TLD has no RDAP."
        case .health:
            return
                "Check that a domain's DNS is delegated and served correctly, by asking every one of its nameservers directly, and that the certificate its website serves is valid."
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

/// A start-panel example: what goes in the bar, and why it is interesting.
struct ModeExample: Hashable {
    var name: String
    var type: String?
    var note: String?
    var several = false
}
