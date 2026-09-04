import Foundation
import NordygCore

/// Error surfaced by the core or by the bridge itself.
struct CoreError: Error, LocalizedError {
    var code: String
    var message: String
    var details: JSONValue?
    var errorDescription: String? { message }
}

private struct Request<P: Encodable>: Encodable {
    var id: String
    var op: String
    var params: P?
}

private struct Envelope<R: Decodable>: Decodable {
    var id: String
    var ok: Bool
    var result: R?
    var error: BridgeError?
}

/// The only place that touches the C surface. Calls block a background
/// thread; Swift cancellation maps to NordygCancel.
final class Core: @unchecked Sendable {
    static let shared = Core()

    private let queue = DispatchQueue(label: "foo.n0rdy.nordyg.core", qos: .userInitiated, attributes: .concurrent)
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.keyEncodingStrategy = .convertToSnakeCase
        return e
    }()
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()

    func call<P: Encodable, R: Decodable>(_ op: String, _ params: P) async throws -> R {
        let id = UUID().uuidString
        let body = try encoder.encode(Request(id: id, op: op, params: params))
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<R, Error>) in
                queue.async {
                    cont.resume(with: Result { try self.invoke(body) })
                }
            }
        } onCancel: {
            id.withCString { NordygCancel($0) }
        }
    }

    func call<R: Decodable>(_ op: String) async throws -> R {
        try await call(op, EmptyParams())
    }

    private func invoke<R: Decodable>(_ body: Data) throws -> R {
        let json = String(decoding: body, as: UTF8.self)
        guard let raw = json.withCString({ NordygQuery($0) }) else {
            throw CoreError(code: "bridge", message: "core returned no response")
        }
        defer { NordygFree(raw) }
        let data = Data(bytes: raw, count: strlen(raw))
        let env = try decoder.decode(Envelope<R>.self, from: data)
        if env.ok, let r = env.result { return r }
        let e = env.error ?? BridgeError(code: "internal", message: "malformed envelope", details: nil)
        throw CoreError(code: e.code, message: e.message, details: e.details)
    }
}
