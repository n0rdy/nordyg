import Foundation

// Swift mirror of context/contract.md. Property names are camelCase; the coder
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

extension Options {
    /// Short names of the options that differ from the core's defaults.
    var changed: [String] {
        var out: [String] = []
        if recursionDesired == false { out.append("RD off") }
        if dnssecOk == false { out.append("DO off") }
        if checkingDisabled == true { out.append("CD on") }
        if edns == false { out.append("EDNS off") }
        if tcpFallback == false { out.append("no TCP fallback") }
        if nsid == true { out.append("NSID") }
        if cookie == true { out.append("cookie") }
        if let u = udpSize, u != 1232 { out.append("UDP \(u)") }
        if let t = timeoutMs, t != 5000 { out.append("timeout \(t) ms") }
        return out
    }
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
    /// Chains for answer RRsets signed by another zone (CNAME into another zone).
    var related: [DNSSECRelated]?
}
struct DNSSECRelated: Codable, Hashable {
    var name: String
    var type: String
    var signer: String
    var status: String
    var reason: String
    var chain: [DNSSECLink]
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
    /// Export the walk from the root (dig +trace); endpoint is then ignored.
    var trace: Bool? = nil
}
struct ExportResult: Codable { var command: String }

struct PingResult: Codable { var contractVersion: Int; var version: String; var ops: [String] }

// MARK: rdap

struct RDAPParams: Codable {
    var domain: String
    var endpoint: Endpoint
    var options: Options
    var bootstrap: [Endpoint]
}
struct RDAPEvent: Codable, Hashable { var action: String; var date: String }
struct RDAPContact: Codable, Hashable { var roles: [String]; var handle: String?; var name: String?; var org: String?; var email: String?; var phone: String? }
struct RDAPRegistrar: Codable, Hashable { var name: String?; var ianaId: String?; var url: String?; var abuseEmail: String?; var abusePhone: String? }
struct RDAPStatus: Codable, Hashable { var code: String; var meaning: String }
struct RDAPDS: Codable, Hashable { var keyTag: Int; var algorithm: Int; var digestType: Int; var digest: String }
struct RDAPDNSSEC: Codable, Hashable { var known: Bool; var signed: Bool; var ds: [RDAPDS] }
struct RDAPResult: Codable, Hashable {
    var domain: String
    var source: String
    var server: String
    var registrarServer: String?
    var found: Bool
    var handle: String?
    var status: [RDAPStatus]
    var registered: String?
    var expires: String?
    var updated: String?
    var expiresInDays: Int?
    var registrar: RDAPRegistrar
    var contacts: [RDAPContact]
    var nameservers: [String]
    var dnsNameservers: [String]
    var nsMismatch: Bool
    var dnssec: RDAPDNSSEC
    var events: [RDAPEvent]
    var notices: [String]
    var warnings: [String]
    var raw: String
    var bootstrapSource: String
}

// MARK: email

// MARK: health (contract §8d)

struct HealthParams: Codable {
    var domain: String
    var endpoint: Endpoint
    var options: Options
    var bootstrap: [Endpoint]
}
struct HealthDelegation: Codable, Hashable {
    var parent: String
    var parentNs: [String]
    var childNs: [String]
    var verdict: Verdict
    var findings: [Verdict]
}
struct HealthServer: Codable, Hashable {
    var name: String
    var ip: String
    var atParent: Bool
    var atChild: Bool
    var answered: Bool
    var skipped: Bool
    var authoritative: Bool
    var rcode: String?
    var serial: UInt32?
    var ns: [String]
    var tcp: Bool
    var edns: Bool
    var signed: Bool
    var axfr: String
    var recursion: Bool
    var rttMs: Double
    var error: String?
    var status: String
    var problems: [Verdict]
}
struct HealthNameservers: Codable, Hashable { var servers: [HealthServer]; var verdict: Verdict; var findings: [Verdict] }
struct HealthSerialGroup: Codable, Hashable { var serial: UInt32; var servers: [String] }
struct HealthSOA: Codable, Hashable { var record: Record?; var serials: [HealthSerialGroup]; var verdict: Verdict; var findings: [Verdict] }
struct HealthGlueEntry: Codable, Hashable { var name: String; var inBailiwick: Bool; var parent: [String]; var child: [String]; var match: Bool }
struct HealthGlue: Codable, Hashable { var entries: [HealthGlueEntry]; var verdict: Verdict; var findings: [Verdict] }
struct HealthDNSSEC: Codable, Hashable { var status: String; var ds: [Record]; var result: DNSSECResult?; var verdict: Verdict; var findings: [Verdict] }
struct HealthCAARecord: Codable, Hashable { var flags: Int; var tag: String; var value: String }
struct HealthCAA: Codable, Hashable { var foundAt: String?; var records: [HealthCAARecord]; var verdict: Verdict; var findings: [Verdict] }
struct TLSCert: Codable, Hashable { var subject: String; var issuer: String; var names: [String]?; var notBefore: String; var notAfter: String; var sha256: String; var spkiSha256: String }
struct TLSRevocation: Codable, Hashable { var subject: String; var revokedAt: String; var reason: String }
/// What one web server address presented on port 443 (certs.Probe).
struct TLSProbe: Codable, Hashable {
    var name: String
    var ip: String
    var port: Int
    var connected: Bool
    var skipped: Bool
    var error: String?
    var tlsVersion: String?
    var chain: [TLSCert]
    var trusted: Bool
    var trustError: String?
    var nameMatch: Bool
    var expiresInDays: Int
    var revoked: [TLSRevocation]
    var revocationChecked: Bool
    var revocationNote: String?
}
struct HealthHTTPSHost: Codable, Hashable { var name: String; var tlsa: [String]; var tlsaStatus: String?; var tlsaMatch: Bool?; var tlsaError: String?; var servers: [TLSProbe] }
struct HealthHTTPS: Codable, Hashable { var hosts: [HealthHTTPSHost]; var verdict: Verdict; var findings: [Verdict] }
struct HealthResult: Codable, Hashable {
    var domain: String
    var zone: String
    var delegation: HealthDelegation
    var nameservers: HealthNameservers
    var soa: HealthSOA
    var glue: HealthGlue
    var dnssec: HealthDNSSEC
    var caa: HealthCAA
    var https: HealthHTTPS
    var overall: Verdict
}

struct EmailParams: Codable {
    var domain: String
    var endpoint: Endpoint
    var options: Options
    var bootstrap: [Endpoint]
    var extraDkimSelectors: [String]
}
struct Verdict: Codable, Hashable { var status: String; var message: String }
struct PTRCheck: Codable, Hashable { var ip: String; var names: [String]; var matches: Bool; var error: String? }
struct MXHost: Codable, Hashable { var preference: Int; var exchange: String; var addresses: [String]; var ptr: [PTRCheck]; var error: String? }
struct MXSection: Codable, Hashable { var hosts: [MXHost]; var nullMx: Bool; var implicit: Bool; var verdict: Verdict }
struct SPFInclude: Codable, Hashable { var name: String; var via: String; var depth: Int; var record: String?; var decoded: JSONValue?; var lookups: Int; var error: String? }
struct SPFSection: Codable, Hashable { var records: [String]; var decoded: JSONValue?; var includes: [SPFInclude]; var totalLookups: Int; var verdict: Verdict }
struct DKIMSelector: Codable, Hashable { var selector: String; var name: String; var found: Bool; var record: String?; var decoded: JSONValue? }
struct DKIMSection: Codable, Hashable { var selectors: [DKIMSelector]; var wildcard: Bool?; var verdict: Verdict }
struct DMARCSection: Codable, Hashable { var name: String; var records: [String]; var decoded: JSONValue?; var verdict: Verdict }
struct MTASTSPolicy: Codable, Hashable { var version: String; var mode: String; var mx: [String]; var maxAge: Int }
struct MTASTSSection: Codable, Hashable { var name: String; var record: String?; var id: String?; var policyUrl: String?; var policyText: String?; var policy: MTASTSPolicy?; var error: String?; var verdict: Verdict }
struct DANEServer: Codable, Hashable { var ip: String; var checked: Bool; var match: Bool; var skipped: Bool?; var error: String? }
struct DANEHost: Codable, Hashable { var exchange: String; var tlsa: [String]; var status: String?; var error: String?; var servers: [DANEServer] }
struct DANESection: Codable, Hashable { var mxStatus: String?; var hosts: [DANEHost]; var findings: [Verdict]; var verdict: Verdict }
struct BIMISection: Codable, Hashable { var name: String; var record: String?; var logo: String?; var evidence: String?; var verdict: Verdict }
struct DNSBLCheck: Codable, Hashable { var ip: String; var zone: String; var listed: Bool; var blocked: Bool; var response: String?; var error: String? }
struct DNSBLSection: Codable, Hashable { var checks: [DNSBLCheck]; var verdict: Verdict }
struct EmailResult: Codable, Hashable {
    var domain: String
    var mx: MXSection
    var spf: SPFSection
    var dkim: DKIMSection
    var dmarc: DMARCSection
    var mtaSts: MTASTSSection
    var dane: DANESection
    var transport: Verdict
    var bimi: BIMISection
    var dnsbl: DNSBLSection
    var overall: Verdict
}

/// Record types offered in the picker. "ALL" is a shell-side fan-out.
enum RecordTypes {
    static let common = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "DS", "DNSKEY", "TLSA", "HTTPS", "SVCB", "NAPTR", "ANY"]
    static let fanOut = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "HTTPS"]
    static let all = ["ALL"] + common
}

extension Message {
    /// RFC 8767: the resolver served this answer past its TTL and said so.
    var isStale: Bool { edns?.options.contains { $0.ede?.infoCode == 3 } ?? false }
    /// RFC 8914 EDE 15–18: Blocked, Censored, Filtered, Prohibited.
    var isFiltered: Bool { edns?.options.contains { (15...18).contains($0.ede?.infoCode ?? 0) } ?? false }
    var addresses: [String] { answer.compactMap { ($0.type == "A" || $0.type == "AAAA") ? $0.rdata : nil } }
}
