import Foundation
import SystemConfiguration

/// Reads the resolvers macOS actually uses, per interface, via the dynamic
/// store. The core never touches the system resolver itself; these become
/// explicit endpoints and the bootstrap list for DoH.
enum SystemResolvers {
    struct Entry: Hashable {
        var interface: String?
        var addresses: [String]
        var searchDomains: [String]
    }

    static func current() -> [Entry] {
        guard let store = SCDynamicStoreCreate(nil, "Nordyg" as CFString, nil, nil) else { return [] }
        var out: [Entry] = []
        if let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any] {
            out.append(entry(from: global, interface: nil))
        }
        let pattern = "State:/Network/Service/[^/]+/DNS" as CFString
        if let keys = SCDynamicStoreCopyKeyList(store, pattern) as? [String] {
            for key in keys.sorted() {
                guard let dict = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any] else { continue }
                let e = entry(from: dict, interface: dict["InterfaceName"] as? String ?? serviceName(store, key))
                if !e.addresses.isEmpty && !out.contains(where: { $0.addresses == e.addresses }) {
                    out.append(e)
                }
            }
        }
        return out.filter { !$0.addresses.isEmpty }
    }

    /// Endpoints for the picker: one per resolver address, labelled by interface.
    static func endpoints() -> [Endpoint] {
        var seen = Set<String>()
        var out: [Endpoint] = []
        for e in current() {
            for ip in e.addresses where seen.insert(ip).inserted {
                let label = e.interface.map { "System (\($0)) \(ip)" } ?? "System \(ip)"
                out.append(Endpoint(transport: "udp", address: hostPort(ip, 53), label: label))
            }
        }
        return out
    }

    private static func entry(from dict: [String: Any], interface: String?) -> Entry {
        Entry(interface: interface,
              addresses: dict["ServerAddresses"] as? [String] ?? [],
              searchDomains: dict["SearchDomains"] as? [String] ?? [])
    }

    private static func serviceName(_ store: SCDynamicStore, _ dnsKey: String) -> String? {
        let ipv4Key = dnsKey.replacingOccurrences(of: "/DNS", with: "/IPv4")
        return (SCDynamicStoreCopyValue(store, ipv4Key as CFString) as? [String: Any])?["InterfaceName"] as? String
    }

    static func hostPort(_ ip: String, _ port: Int) -> String {
        ip.contains(":") ? "[\(ip)]:\(port)" : "\(ip):\(port)"
    }
}
