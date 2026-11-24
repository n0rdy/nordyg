import AppKit
import SwiftUI

/// The header flags worth saying out loud, in words. QR (it is a response)
/// and RD (echo of the request) are always set and say nothing; RA is only
/// news when it is missing; AD is the resolver's own DNSSEC claim, which the
/// DNSSEC badge already covers with Nordyg's own check.
enum FlagNotes {
    static func notes(_ f: Flags) -> [String] {
        var out: [String] = []
        if f.aa { out.append("authoritative answer") }
        if f.tc { out.append("truncated") }
        if f.rd && !f.ra { out.append("server does not recurse") }
        return out
    }
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
            return
                "\(prose(zone)) is not signed with DNSSEC. \(proseZone(parent).capitalizedFirst) confirms there is no DS record, so there is nothing to validate. This is the normal state for most domains."
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

/// Hover explanations for the labels in the status strips.
enum Glossary {
    static func rcode(_ r: String) -> String {
        switch r {
        case "NOERROR":
            return
                "Response code NOERROR: the server answered normally. Note that NOERROR with zero records means the name exists but has no records of this type."
        case "NXDOMAIN":
            return "Response code NXDOMAIN: the name does not exist. The authority section usually carries the zone's SOA record."
        case "SERVFAIL":
            return
                "Response code SERVFAIL: the server could not answer. Common causes are DNSSEC validation failure at the resolver, lame delegations or an unreachable authoritative server."
        case "REFUSED":
            return
                "Response code REFUSED: the server refused the query by policy, for example a recursive query sent to an authoritative-only server."
        case "FORMERR": return "Response code FORMERR: the server could not parse the query."
        case "NOTIMP": return "Response code NOTIMP: the server does not implement this kind of query."
        case "BADVERS", "BADSIG":
            return "Extended response code BADVERS/BADSIG: the server rejected the EDNS version or a transaction signature."
        case "BADCOOKIE": return "Extended response code BADCOOKIE: the server did not accept the DNS cookie sent with the query."
        default: return "Response code \(r), see the IANA DNS RCODE registry."
        }
    }

    static func dnssec(_ s: String) -> String {
        switch s {
        case "secure":
            return
                "DNSSEC secure: every link from the root trust anchor down to this answer was verified by Nordyg itself. The data is exactly what the zone owner signed."
        case "insecure":
            return
                "DNSSEC unsigned: this zone has no DS record at its parent, and the parent proved that. Nothing is wrong. The domain simply does not use DNSSEC, like most domains."
        case "bogus":
            return
                "DNSSEC bogus: a signature, key or DS record failed verification. Either the zone is misconfigured (expired signatures, key rollover gone wrong) or the answer was tampered with. Validating resolvers refuse such answers."
        default:
            return
                "DNSSEC indeterminate: Nordyg could not fetch something it needed (a DNSKEY or DS lookup failed or timed out), so no verdict is possible."
        }
    }

    static let latency =
        "Round-trip time of the whole exchange, including connection setup and any TLS handshake. For fan-out queries the slowest one is shown."
    static let size =
        "Size of the response message on the wire, in bytes. Over 1232 bytes a UDP answer risks fragmentation and may be truncated."
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
            "ra": "RA: the server offers recursion",
            "ad": "AD: the resolver says it validated the answer with DNSSEC (Nordyg verifies independently)",
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
        case "SOA": return "SOA: start of authority. Holds the zone serial, refresh timers and the negative-caching TTL."
        case "PTR": return "PTR: reverse mapping from an address back to a name."
        case "SRV": return "SRV: service location with priority, weight, port and target."
        case "CAA": return "CAA: which certificate authorities may issue certificates for the name."
        case "DS":
            return "DS: delegation signer, the parent's hash of the child's key-signing key. The link between zones in the DNSSEC chain."
        case "DNSKEY": return "DNSKEY: public key used to sign the zone. KSK signs the key set, ZSK signs the data."
        case "RRSIG": return "RRSIG: DNSSEC signature over a record set, with inception and expiration times."
        case "NSEC": return "NSEC: proves a name or type does not exist, by naming the next name in the zone."
        case "NSEC3": return "NSEC3: hashed version of NSEC, optionally with opt-out for unsigned delegations."
        case "NSEC3PARAM": return "NSEC3PARAM: the hashing parameters a zone uses for NSEC3."
        case "TLSA": return "TLSA: DANE binding of a TLS certificate or key to a service name."
        case "HTTPS": return "HTTPS: service binding for web endpoints. Advertises ALPN (h2, h3), ports, address hints and ECH."
        case "SVCB": return "SVCB: general service binding, the base of HTTPS records."
        case "NAPTR": return "NAPTR: naming authority pointer, used by ENUM and SIP."
        case "SSHFP": return "SSHFP: fingerprint of an SSH host key."
        case "ANY": return "ANY: asks for all types. Deprecated (RFC 8482), so many servers answer minimally."
        default:
            if t.uppercased().hasPrefix("TYPE") {
                return "\(t): a record type Nordyg has no parser for. The data is shown as raw hex (RFC 3597)."
            }
            return "Record type \(t)."
        }
    }
}

extension Glossary {
    static let cacheUnknown =
        "Click to find out how old this resolver's copy is. Nordyg fetches the authoritative answer with a trace and compares TTLs. The difference is the time the record has sat in the resolver's cache."
    static let cacheChecking = "Tracing to the authoritative server to learn the original TTL…"
    static let cacheFresh = "The TTL matches the authoritative one: the resolver fetched this answer just now, not from its cache."
    static func cacheAge(_ s: Int) -> String {
        "The resolver returned a TTL \(s) s lower than the authoritative server publishes, so this copy has been in its cache about that long. Changes made since then are not visible through this resolver until the TTL runs out."
    }
    static let cacheDiffers =
        "The resolver's answer contains data the authoritative server does not currently publish, or a TTL higher than the original. Either a change is still propagating, the resolver overrides or filters this name, or it serves a geographic variant."
    static let stale =
        "The resolver flagged this answer as stale (Extended DNS Error 3, RFC 8767): it is past its TTL and was served because a fresh fetch failed or is still in progress."
    static func systemView(_ addrs: [String], overlap: Bool) -> String {
        let list = addrs.isEmpty ? "nothing" : addrs.joined(separator: ", ")
        return
            "What this Mac's own resolver (mDNSResponder) returns for the name right now: \(list).\nEvery ordinary app, Safari included, uses that cache. Nordyg queries resolvers directly and bypasses it."
            + (overlap ? "" : "\nThe Mac sees something different from this answer: its cache is stale, or it uses another resolver.")
    }
}

/// Transport names as people write them: DoT, DoH and DoQ, not DOT.
enum TransportName {
    static func display(_ p: String) -> String {
        switch p.lowercased() {
        case "dot": return "DoT"
        case "doh": return "DoH"
        case "doq": return "DoQ"
        default: return p.uppercased()
        }
    }
}
