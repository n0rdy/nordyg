import SwiftUI

/// Semantic colour for record types, the way database tools colour column
/// types. Related types share a hue so a table reads at a glance.
enum TypeStyle {
    static func color(_ type: String) -> Color {
        switch type.uppercased() {
        case "A": return .blue
        case "AAAA": return .teal
        case "CNAME", "DNAME": return .gray
        case "MX": return .purple
        case "TXT", "SPF": return .orange
        case "NS": return .green
        case "SOA": return .brown
        case "PTR": return .mint
        case "SRV", "NAPTR", "TLSA", "SSHFP": return .cyan
        case "CAA": return .pink
        case "HTTPS", "SVCB": return .indigo
        case "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "CDS", "CDNSKEY": return .yellow
        default: return .secondary
        }
    }
}

struct TypeBadge: View {
    var type: String
    var body: some View {
        Text(type)
            .help(Glossary.recordType(type))
            .font(.system(.caption, design: .monospaced).weight(.bold))
            .foregroundStyle(TypeStyle.color(type))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .frame(minWidth: 44)
            .background(TypeStyle.color(type).opacity(0.16))
            .clipShape(RoundedRectangle(cornerRadius: 5))
    }
}

/// A compact status chip.
struct Pill: View {
    var text: String
    var icon: String?
    var color: Color = .secondary
    var mono = false
    var help: String?

    var body: some View {
        HStack(spacing: 4) {
            if let icon { Image(systemName: icon).foregroundStyle(color) }
            Text(text)
                .font(mono ? .system(.caption, design: .monospaced).weight(.semibold) : .caption.weight(.semibold))
        }
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(color.opacity(0.14))
        .clipShape(Capsule())
        .help(help ?? "")
    }
}

/// A slim row holding the view switcher for a result, kept apart from the
/// pill strip so neither has to fit the other.
struct TabRow<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        HStack {
            content
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }
}

/// The row of pills under the command bar summarising a result.
struct StatusStrip<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) { content }
                .padding(.horizontal, 12).padding(.vertical, 7)
        }
        .background(.bar)
    }
}

enum Rcode {
    static func color(_ rcode: String) -> Color {
        switch rcode {
        case "NOERROR": return .green
        case "NXDOMAIN": return .orange
        default: return .red
        }
    }
}

struct RcodeBadge: View {
    var rcode: String
    var body: some View { Pill(text: rcode, color: Rcode.color(rcode), mono: true, help: Glossary.rcode(rcode)) }
}

enum DNSSECStyle {
    static func color(_ status: String) -> Color {
        switch status {
        case "secure": return .green
        case "insecure": return .gray
        case "bogus": return .red
        default: return .orange
        }
    }
    static func icon(_ status: String) -> String {
        switch status {
        case "secure": return "lock.fill"
        case "insecure": return "lock.open"
        case "bogus": return "xmark.shield.fill"
        default: return "questionmark.circle"
        }
    }
}

struct StatusBadge: View {
    var status: String
    var body: some View {
        Pill(text: DNSSECWording.label(status), icon: DNSSECStyle.icon(status), color: DNSSECStyle.color(status), help: Glossary.dnssec(status))
    }
    var color: Color { DNSSECStyle.color(status) }
}

func ms(_ v: Double) -> String { v < 10 ? String(format: "%.1f ms", v) : String(format: "%.0f ms", v) }

/// Names for prose: no trailing dot, and TLDs written as ".me" so they do
/// not read like words.
func prose(_ name: String) -> String {
    name == "." ? "the root" : String(name.hasSuffix(".") ? name.dropLast() : Substring(name))
}

func proseZone(_ zone: String) -> String {
    let bare = zone.hasSuffix(".") ? String(zone.dropLast()) : zone
    if bare.isEmpty { return "the root zone" }
    return bare.contains(".") ? "the zone \(bare)" : "the .\(bare) zone"
}

extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}

/// Plain-language wording for DNSSEC verdicts. "insecure" is DNSSEC jargon
/// for "not signed" and reads as alarming, so the UI says "unsigned".
enum DNSSECWording {
    static func label(_ status: String) -> String {
        switch status {
        case "secure": return "secure"
        case "insecure": return "unsigned"
        case "bogus": return "bogus"
        default: return "indeterminate"
        }
    }

    static func headline(_ r: DNSSECResult) -> String {
        switch r.status {
        case "secure":
            return "Signed and validated from the root down."
        case "insecure":
            let zone = r.chain.last { $0.status == "insecure" }?.zone ?? r.chain.last?.zone ?? "This name"
            let parent = r.chain.last { $0.status == "secure" }?.zone ?? "its parent"
            return "\(prose(zone)) is not signed with DNSSEC. \(proseZone(parent).capitalizedFirst) confirms there is no DS record, so there is nothing to validate. This is the normal state for most domains."
        case "bogus":
            return "Validation failed. The data cannot be trusted, or the zone is misconfigured."
        default:
            return "Could not decide: something needed for validation was unavailable."
        }
    }

    static func detail(_ r: DNSSECResult) -> String? {
        r.reason.isEmpty ? nil : r.reason
    }
}

func severityIcon(_ s: String) -> String {
    switch s { case "error": return "xmark.octagon.fill"; case "warning": return "exclamationmark.triangle.fill"; default: return "info.circle" }
}
func severityColor(_ s: String) -> Color {
    switch s { case "error": return .red; case "warning": return .orange; default: return .secondary }
}

enum Pasteboard {
    static func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}

/// Reduced-motion aware animation for result changes.
struct ResultAnimation: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduce
    var value: Int
    func body(content: Content) -> some View {
        content.animation(reduce ? nil : .easeOut(duration: 0.18), value: value)
    }
}

/// Hover explanations for the labels in the status strips.
enum Glossary {
    static func rcode(_ r: String) -> String {
        switch r {
        case "NOERROR": return "Response code NOERROR: the server answered normally. Note that NOERROR with zero records means the name exists but has no records of this type."
        case "NXDOMAIN": return "Response code NXDOMAIN: the name does not exist. The authority section usually carries the zone's SOA record."
        case "SERVFAIL": return "Response code SERVFAIL: the server could not answer. Common causes are DNSSEC validation failure at the resolver, lame delegations or an unreachable authoritative server."
        case "REFUSED": return "Response code REFUSED: the server refused the query by policy, for example a recursive query sent to an authoritative-only server."
        case "FORMERR": return "Response code FORMERR: the server could not parse the query."
        case "NOTIMP": return "Response code NOTIMP: the server does not implement this kind of query."
        case "BADVERS", "BADSIG": return "Extended response code BADVERS/BADSIG: the server rejected the EDNS version or a transaction signature."
        case "BADCOOKIE": return "Extended response code BADCOOKIE: the server did not accept the DNS cookie sent with the query."
        default: return "Response code \(r), see the IANA DNS RCODE registry."
        }
    }

    static func dnssec(_ s: String) -> String {
        switch s {
        case "secure": return "DNSSEC secure: every link from the root trust anchor down to this answer was verified by Nordyg itself. The data is exactly what the zone owner signed."
        case "insecure": return "DNSSEC unsigned: this zone has no DS record at its parent, and the parent proved that. Nothing is wrong; the domain simply does not use DNSSEC, like most domains."
        case "bogus": return "DNSSEC bogus: a signature, key or DS record failed verification. Either the zone is misconfigured (expired signatures, key rollover gone wrong) or the answer was tampered with. Validating resolvers refuse such answers."
        default: return "DNSSEC indeterminate: Nordyg could not fetch something it needed (a DNSKEY or DS lookup failed or timed out), so no verdict is possible."
        }
    }

    static let latency = "Round-trip time of the whole exchange, including connection setup and any TLS handshake. For fan-out queries the slowest one is shown."
    static let size = "Size of the response message on the wire, in bytes. Over 1232 bytes a UDP answer risks fragmentation and may be truncated."
    static let server = "The resolver that answered, as labelled in the resolver picker."
    static let hops = "Number of servers asked, from a root server down to the authoritative server for the name."
    static let totalTime = "Sum of the round-trip times of all hops."
    static let answers = "Records in the answer section of the final response."

    static func transport(_ t: String, truncated: Bool) -> String {
        var s: String
        switch t.lowercased() {
        case "udp": s = "Plain DNS over UDP port 53, the classic transport. Unencrypted."
        case "tcp": s = "Plain DNS over TCP port 53. Used for large answers and zone transfers. Unencrypted."
        case "dot": s = "DNS over TLS (RFC 7858), port 853. Encrypted and authenticated by the server certificate."
        case "doh": s = "DNS over HTTPS (RFC 8484). Encrypted, looks like ordinary web traffic."
        case "doq": s = "DNS over QUIC (RFC 9250), port 853. Encrypted, with faster connection setup than TLS over TCP."
        default: s = "Transport \(t)."
        }
        if truncated { s += " The UDP answer was truncated (TC bit), so the query was retried over TCP." }
        return s
    }

    static func flags(_ set: [String]) -> String {
        let names: [String: String] = [
            "qr": "QR: this is a response", "aa": "AA: authoritative answer, straight from a server for the zone",
            "tc": "TC: truncated, the answer did not fit", "rd": "RD: recursion was requested",
            "ra": "RA: the server offers recursion", "ad": "AD: the resolver says it validated the answer with DNSSEC (Nordyg verifies independently)",
            "cd": "CD: checking disabled, the resolver was asked not to validate",
        ]
        return "Header flags set in the response.\n" + set.map { names[$0] ?? $0 }.joined(separator: "\n")
    }

    static func recordType(_ t: String) -> String {
        switch t.uppercased() {
        case "A": return "A: IPv4 address."
        case "AAAA": return "AAAA: IPv6 address."
        case "CNAME": return "CNAME: alias to another name. Lookups continue at the target."
        case "DNAME": return "DNAME: alias for a whole subtree of names."
        case "MX": return "MX: mail exchanger for the domain, with a preference (lower is tried first)."
        case "TXT": return "TXT: free text. Carries SPF, DMARC, DKIM and verification tokens."
        case "NS": return "NS: nameserver authoritative for the zone."
        case "SOA": return "SOA: start of authority; zone serial, refresh timers and the negative-caching TTL."
        case "PTR": return "PTR: reverse mapping from an address back to a name."
        case "SRV": return "SRV: service location with priority, weight, port and target."
        case "CAA": return "CAA: which certificate authorities may issue certificates for the name."
        case "DS": return "DS: delegation signer; the parent's hash of the child's key-signing key. The link between zones in the DNSSEC chain."
        case "DNSKEY": return "DNSKEY: public key used to sign the zone. KSK signs the key set, ZSK signs the data."
        case "RRSIG": return "RRSIG: DNSSEC signature over a record set, with inception and expiration times."
        case "NSEC": return "NSEC: proves a name or type does not exist, by naming the next name in the zone."
        case "NSEC3": return "NSEC3: hashed version of NSEC, optionally with opt-out for unsigned delegations."
        case "NSEC3PARAM": return "NSEC3PARAM: the hashing parameters a zone uses for NSEC3."
        case "TLSA": return "TLSA: DANE binding of a TLS certificate or key to a service name."
        case "HTTPS": return "HTTPS: service binding for web endpoints; advertises ALPN (h2, h3), ports, address hints and ECH."
        case "SVCB": return "SVCB: general service binding, the base of HTTPS records."
        case "NAPTR": return "NAPTR: naming authority pointer, used by ENUM and SIP."
        case "SSHFP": return "SSHFP: fingerprint of an SSH host key."
        case "ANY": return "ANY: asks for all types. Deprecated (RFC 8482); many servers answer minimally."
        default:
            if t.uppercased().hasPrefix("TYPE") { return "\(t): a record type Nordyg has no parser for. The data is shown as raw hex (RFC 3597)." }
            return "Record type \(t)."
        }
    }
}

/// Pill showing how old a resolver's copy is, with a button to find out.
struct CacheAgePill: View {
    @EnvironmentObject var model: AppModel
    var message: Message
    var question: Question

    var body: some View {
        switch model.cacheAge(of: message, question: question) {
        case .unknown:
            Button { model.fetchAuthoritative(for: question) } label: {
                Pill(text: "cache age?", icon: "questionmark.circle", help: Glossary.cacheUnknown)
            }
            .buttonStyle(.plain)
        case .checking:
            Pill(text: "checking…", icon: "hourglass", help: Glossary.cacheChecking)
        case .fresh:
            Pill(text: "fresh", icon: "sparkles", color: .green, help: Glossary.cacheFresh)
        case .cached(let s):
            Pill(text: "cached \(age(s)) ago", icon: "clock.arrow.circlepath", color: s > 300 ? .orange : .secondary, help: Glossary.cacheAge(s))
        case .differs:
            Pill(text: "differs from authoritative", icon: "exclamationmark.triangle.fill", color: .orange, help: Glossary.cacheDiffers)
        }
    }

    func age(_ s: Int) -> String {
        if s < 60 { return "\(s) s" }
        if s < 3600 { return "\(s / 60) min" }
        if s < 86400 { return String(format: "%.1f h", Double(s) / 3600) }
        return String(format: "%.1f d", Double(s) / 86400)
    }
}

struct StalePill: View {
    var body: some View { Pill(text: "stale", icon: "exclamationmark.arrow.circlepath", color: .orange, help: Glossary.stale) }
}

/// What this Mac's own resolver returns, next to what Nordyg got.
struct SystemViewPill: View {
    var system: [String]?
    var answers: [String]

    var body: some View {
        if let system {
            let overlap = !Set(system).isDisjoint(with: Set(answers))
            let color: Color = system.isEmpty ? .secondary : (overlap ? .green : .orange)
            Pill(text: system.isEmpty ? "Mac sees nothing" : (overlap ? "Mac agrees" : "Mac sees different"),
                 icon: "desktopcomputer", color: color,
                 help: Glossary.systemView(system, overlap: overlap))
        }
    }
}

extension Glossary {
    static let cacheUnknown = "Click to find out how old this resolver's copy is. Nordyg fetches the authoritative answer with a trace and compares TTLs; the difference is the time the record has sat in the resolver's cache."
    static let cacheChecking = "Tracing to the authoritative server to learn the original TTL…"
    static let cacheFresh = "The TTL matches the authoritative one: the resolver fetched this answer just now, not from its cache."
    static func cacheAge(_ s: Int) -> String { "The resolver returned a TTL \(s) s lower than the authoritative server publishes, so this copy has been in its cache about that long. Changes made since then are not visible through this resolver until the TTL runs out." }
    static let cacheDiffers = "The resolver's answer contains data the authoritative server does not currently publish, or a TTL higher than the original. Either a change is still propagating, the resolver overrides or filters this name, or it serves a geographic variant."
    static let stale = "The resolver flagged this answer as stale (Extended DNS Error 3, RFC 8767): it is past its TTL and was served because a fresh fetch failed or is still in progress."
    static func systemView(_ addrs: [String], overlap: Bool) -> String {
        let list = addrs.isEmpty ? "nothing" : addrs.joined(separator: ", ")
        return "What this Mac's own resolver (mDNSResponder) returns for the name right now: \(list).\nEvery ordinary app, Safari included, uses that cache. Nordyg queries resolvers directly and bypasses it." + (overlap ? "" : "\nThe Mac sees something different from this answer: its cache is stale, or it uses another resolver.")
    }
}

enum VerdictStyle {
    static func color(_ status: String) -> Color {
        switch status {
        case "ok": return .green
        case "warn": return .orange
        case "fail": return .red
        default: return .secondary
        }
    }
    static func icon(_ status: String) -> String {
        switch status {
        case "ok": return "checkmark.circle.fill"
        case "warn": return "exclamationmark.triangle.fill"
        case "fail": return "xmark.octagon.fill"
        default: return "info.circle"
        }
    }
    static func label(_ status: String) -> String {
        switch status {
        case "ok": return "OK"
        case "warn": return "warning"
        case "fail": return "failing"
        default: return "info"
        }
    }
}

struct VerdictPill: View {
    var verdict: Verdict
    var body: some View {
        Pill(text: VerdictStyle.label(verdict.status), icon: VerdictStyle.icon(verdict.status), color: VerdictStyle.color(verdict.status), help: verdict.message)
    }
}
