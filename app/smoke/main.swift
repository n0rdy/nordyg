// Bridge smoke harness: proves the three-function C surface works from Swift
// on the built archive. No network by default; set NORDYG_SMOKE_NET=1 to add a
// live query. Run via `make smoke`.

import Foundation
import NordygCore

struct BridgeError: Decodable { let code: String; let message: String }
struct Envelope<T: Decodable>: Decodable {
    let id: String
    let ok: Bool
    let result: T?
    let error: BridgeError?
}
struct Ping: Decodable { let version: String; let ops: [String] }
struct Record: Decodable { let name: String; let type: String; let ttl: UInt32; let rdata: String }
struct Message: Decodable { let rcode: String; let answer: [Record] }
struct Exchange: Decodable { let `protocol`: String; let rtt_ms: Double }
struct Link: Decodable { let zone: String; let status: String }
struct DNSSEC: Decodable { let status: String; let reason: String; let chain: [Link] }
struct QueryResult: Decodable { let message: Message; let exchange: Exchange; let dnssec: DNSSEC? }
struct Hop: Decodable { let zone: String; let server: Server }
struct Server: Decodable { let name: String; let address: String }
struct TraceResult: Decodable { let hops: [Hop]; let final: Message; let dnssec: DNSSEC? }

func call<T: Decodable>(_ op: String, params: [String: Any] = [:], id: String = UUID().uuidString) throws -> Envelope<T> {
    let body = try JSONSerialization.data(withJSONObject: ["id": id, "op": op, "params": params])
    let json = String(decoding: body, as: UTF8.self)
    // const char* on the C side, so the withCString pointer passes straight through.
    guard let raw = json.withCString({ NordygQuery($0) }) else {
        throw NSError(domain: "smoke", code: 1, userInfo: [NSLocalizedDescriptionKey: "NordygQuery returned NULL"])
    }
    defer { NordygFree(raw) }
    return try JSONDecoder().decode(Envelope<T>.self, from: Data(String(cString: raw).utf8))
}

func check(_ cond: Bool, _ msg: String) {
    if !cond { print("FAIL: \(msg)"); exit(1) }
    print("ok   \(msg)")
}

// 1. ping: bridge round trip, id echo, op discovery.
let ping: Envelope<Ping> = try call("ping", id: "smoke-ping")
check(ping.ok && ping.id == "smoke-ping", "ping echoes id")
check(ping.result?.ops.contains("query") == true, "ping lists query op (version \(ping.result?.version ?? "?"))")

// 2. error path: unknown op comes back as a structured error, not a crash.
let bad: Envelope<Ping> = try call("no-such-op")
check(!bad.ok && bad.error?.code == "unknown_op", "unknown op is a structured error")

// 3. malformed JSON straight into the C function.
let mal = "{".withCString { NordygQuery($0) }!
let malText = String(cString: mal)
NordygFree(mal)
check(malText.contains("bad_request"), "malformed JSON is a structured error")

// 4. cancel on an unknown id is a harmless no-op.
"ghost".withCString { NordygCancel($0) }
check(true, "cancel of unknown id does not crash")

// 5. optional live query.
if ProcessInfo.processInfo.environment["NORDYG_SMOKE_NET"] == "1" {
    let q: Envelope<QueryResult> = try call("query", params: [
        "question": ["name": "n0rdy.foo", "type": "A"],
        "endpoint": ["transport": "udp", "address": "1.1.1.1:53"],
    ])
    check(q.ok, "live A query via 1.1.1.1 (\(q.error?.message ?? ""))")
    if let m = q.result?.message {
        print("     rcode=\(m.rcode) rtt=\(q.result!.exchange.rtt_ms)ms via \(q.result!.exchange.`protocol`)")
        for a in m.answer { print("     \(a.name) \(a.ttl) \(a.type) \(a.rdata)") }
    }

    // 6. DNSSEC validation against the live root keys, over DoT.
    let v: Envelope<QueryResult> = try call("query", params: [
        "question": ["name": "cloudflare.com", "type": "A"],
        "endpoint": ["transport": "dot", "address": "1.1.1.1:853", "tls_name": "cloudflare-dns.com"],
        "validate": true,
    ])
    let status = v.result?.dnssec?.status ?? "missing"
    check(v.ok && status == "secure", "cloudflare.com validates as secure via DoT (\(status) \(v.result?.dnssec?.reason ?? v.error?.message ?? ""))")
    for l in v.result?.dnssec?.chain ?? [] { print("     \(l.zone) \(l.status)") }

    // 7. Trace from the real root servers with validation.
    let tr: Envelope<TraceResult> = try call("trace", params: [
        "question": ["name": "cloudflare.com", "type": "A"],
        "validate": true,
    ])
    let tstatus = tr.result?.dnssec?.status ?? "missing"
    check(tr.ok && tstatus == "secure", "trace to cloudflare.com validates as secure (\(tstatus) \(tr.result?.dnssec?.reason ?? tr.error?.message ?? ""))")
    for h in tr.result?.hops ?? [] { print("     \(h.zone) via \(h.server.name) \(h.server.address)") }
}

print("smoke passed")
