import Foundation

/// Resolves a name the way every other app on this Mac does: through the
/// system resolver (mDNSResponder) and its cache. Nordyg's own queries bypass
/// that cache, so this is how a Nordyg-vs-Safari mismatch becomes visible.
/// Reading through the system resolver is allowed in the sandbox; only
/// flushing it is not.
enum SystemLookup {
    static func addresses(for name: String) async -> [String] {
        await Task.detached(priority: .utility) { () -> [String] in
            var hints = addrinfo()
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_STREAM
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(name, nil, &hints, &res) == 0, let first = res else { return [] }
            defer { freeaddrinfo(first) }
            var out: [String] = []
            var p: UnsafeMutablePointer<addrinfo>? = first
            while let ai = p {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let s = String(cString: host)
                    if !out.contains(s) { out.append(s) }
                }
                p = ai.pointee.ai_next
            }
            return out
        }.value
    }
}
