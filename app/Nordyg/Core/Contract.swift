import Foundation

// Swift mirror of docs/contract.md. Property names are camelCase; the coder
// converts to and from snake_case. Unknown fields are ignored on decode so
// the core can add data freely.

struct Endpoint: Codable, Hashable, Identifiable {
    var transport: String
    var address: String?
    var tlsName: String?
    var url: String?
    var method: String?
    var label: String?

    var id: String { "\(transport)|\(address ?? "")|\(url ?? "")|\(tlsName ?? "")" }

    /// Short display: label if set, otherwise a synthesized description.
    var title: String { label ?? summary }
    var summary: String {
        switch transport {
        case "doh": return "\(url ?? "?") (DoH)"
        case "dot": return "\(tlsName ?? address ?? "?") (DoT)"
        case "doq": return "\(tlsName ?? address ?? "?") (DoQ)"
        default: return "\(address ?? "?") (\(transport.uppercased()))"
        }
    }
    var needsPlaceholder: Bool { (url ?? "").contains("{") || (tlsName ?? "").contains("{") }
}

struct Question: Codable, Hashable {
    var name: String
    var type: String
    var qclass: String?
    enum CodingKeys: String, CodingKey { case name, type, qclass = "class" }
}

struct Options: Codable, Hashable {
    var recursionDesired: Bool?
    var dnssecOk: Bool?
    var checkingDisabled: Bool?
    var edns: Bool?
    var udpSize: Int?
    var tcpFallback: Bool?
    var timeoutMs: Int?
    var nsid: Bool?
    var cookie: Bool?
}

struct Flags: Codable, Hashable {
    var qr, aa, tc, rd, ra, ad, cd: Bool
    var set: [String] {
        [("qr", qr), ("aa", aa), ("tc", tc), ("rd", rd), ("ra", ra), ("ad", ad), ("cd", cd)].filter(\.1).map(\.0)
    }
}

struct EDE: Codable, Hashable { var infoCode: Int; var purpose: String; var extraText: String }
struct NSIDInfo: Codable, Hashable { var text: String }
struct EDNSOption: Codable, Hashable {
    var code: Int
    var name: String
    var data: String
    var ede: EDE?
    var nsid: NSIDInfo?
}
struct EDNS: Codable, Hashable {
    var version: Int
    var udpSize: Int
    var dnssecOk: Bool
    var extendedRcode: Int
    var options: [EDNSOption]
}

struct Record: Codable, Hashable {
    var name: String
    var type: String
    var typeCode: Int
    var qclass: String
    var ttl: Int
    var rdata: String
    var fields: [String: JSONValue]?
    var raw: String?
    var decoded: JSONValue?

    enum CodingKeys: String, CodingKey { case name, type, typeCode, qclass = "class", ttl, rdata, fields, raw, decoded }

    /// A name this record points at, if any (for "resolve inline").
    var target: String? {
        for key in ["target", "exchange", "mname"] {
            if let s = fields?[key]?.stringValue, s != "." { return s }
        }
        return nil
    }
}

struct Message: Codable, Hashable {
    var id: Int
    var opcode: String
    var rcode: String
    var flags: Flags
    var question: [Question]
    var answer: [Record]
    var authority: [Record]
    var additional: [Record]
    var edns: EDNS?
    var sizeBytes: Int
    var text: String
}

struct Certificate: Codable, Hashable {
    var subject: String
    var issuer: String
    var dnsNames: [String]
    var notBefore: String
    var notAfter: String
    var sha256: String
}
struct TLSInfo: Codable, Hashable {
    var version: String
    var cipherSuite: String
    var serverName: String
    var alpn: String
    var handshakeMs: Double
    var certificate: Certificate?
}
struct HTTPInfo: Codable, Hashable { var status: Int; var version: String; var contentType: String }
struct Exchange: Codable, Hashable {
    var endpoint: Endpoint
    var `protocol`: String
    var truncatedRetry: Bool
    var rttMs: Double
    var startedAt: String
    var tls: TLSInfo?
    var http: HTTPInfo?
}

struct DNSSECKey: Codable, Hashable {
    var keyTag: Int
    var algorithm: Int
    var algorithmName: String
    var role: String
    var trustAnchor: Bool?
}
struct DNSSECDS: Codable, Hashable { var keyTag: Int; var algorithm: Int; var digestType: Int; var matchesDnskey: Bool }
struct DNSSECSignature: Codable, Hashable {
    var typeCovered: String
    var name: String
    var keyTag: Int
    var signer: String
    var inception: String
    var expiration: String
    var valid: Bool
    var error: String?
    var expiresInMs: Int64
}
struct DNSSECLink: Codable, Hashable {
    var zone: String
    var status: String
    var reason: String?
    var dnskeys: [DNSSECKey]
    var ds: [DNSSECDS]
    var signatures: [DNSSECSignature]
}
struct DNSSECResult: Codable, Hashable {
    var status: String
    var reason: String
    var trustAnchor: DNSSECKey?
    var chain: [DNSSECLink]
    var answerSignatures: [DNSSECSignature]
}

// MARK: ops

struct EmptyParams: Codable {}

struct QueryParams: Codable {
    var question: Question
    var endpoint: Endpoint
    var options: Options
    var validate: Bool
    var bootstrap: [Endpoint]
}
struct QueryResult: Codable, Hashable {
    var questionSent: Question
    var message: Message
    var exchange: Exchange
    var dnssec: DNSSECResult?
}

struct CompareParams: Codable {
    var question: Question
    var endpoints: [Endpoint]
    var options: Options
    var bootstrap: [Endpoint]
}
struct BridgeError: Codable, Hashable, Error {
    var code: String
    var message: String
    var details: JSONValue?
}
struct CompareEntry: Codable, Hashable {
    var endpoint: Endpoint
    var ok: Bool
    var message: Message?
    var exchange: Exchange?
    var error: BridgeError?
}
struct CompareGroup: Codable, Hashable {
    var key: String
    var rcode: String?
    var answers: [String]?
    var members: [Int]
}
struct CompareResult: Codable, Hashable {
    var questionSent: Question
    var results: [CompareEntry]
    var groups: [CompareGroup]
    var consistent: Bool
}

struct TraceParams: Codable {
    var question: Question
    var options: Options
    var validate: Bool
    var bootstrap: [Endpoint]
    var rootHints: [String]?
}
struct TraceServer: Codable, Hashable { var name: String; var address: String }
struct TraceReferral: Codable, Hashable {
    var zone: String
    var nameservers: [String]
    var glue: [String: [String]]
    var ds: [Record]
}
struct TraceHop: Codable, Hashable {
    var zone: String
    var server: TraceServer
    var candidates: [String]
    var message: Message
    var exchange: Exchange
    var referral: TraceReferral?
}
struct TraceResult: Codable, Hashable {
    var questionSent: Question
    var hops: [TraceHop]
    var final: Message
    var dnssec: DNSSECResult?
}

struct Preset: Codable, Hashable, Identifiable {
    var id: String
    var name: String
    var requires: [String]?
    var endpoints: [Endpoint]
}
struct PresetsResult: Codable { var presets: [Preset] }

struct ExportParams: Codable {
    var question: Question
    var endpoint: Endpoint
    var options: Options
    var format: String
}
struct ExportResult: Codable { var command: String }

struct PingResult: Codable { var contractVersion: Int; var version: String; var ops: [String] }

/// Record types offered in the picker. "ALL" is a shell-side fan-out.
enum RecordTypes {
    static let common = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "DS", "DNSKEY", "TLSA", "HTTPS", "SVCB", "NAPTR", "ANY"]
    static let fanOut = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "HTTPS"]
    static let all = ["ALL"] + common
}
