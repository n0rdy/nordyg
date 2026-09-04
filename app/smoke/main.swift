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
struct Record: Decodable { let name: String; let type: String; let ttl: UInt32; let data: String }
struct QueryResult: Decodable { let rcode: String; let answers: [Record]; let rtt_ms: Int }

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
    let q: Envelope<QueryResult> = try call("query", params: ["name": "n0rdy.foo", "type": "A", "server": "1.1.1.1:53"])
    check(q.ok, "live A query via 1.1.1.1 (\(q.error?.message ?? ""))")
    for a in q.result?.answers ?? [] { print("     \(a.name) \(a.ttl) \(a.type) \(a.data)") }
}

print("smoke passed")
