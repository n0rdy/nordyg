import Darwin
import Foundation
import SystemConfiguration

/// The resolver configuration macOS actually uses, as `scutil --dns` prints
/// it: every resolver in order, with the domain it is scoped to, its
/// interface and flags. Read through `dns_configuration_copy` in libSystem,
/// which ordinary name resolution itself uses; the function is stable but its
/// header is not in the public SDK, so it is looked up at run time and the
/// structure is read at fixed offsets (dnsinfo.h, packed to 4 bytes).
/// Returns nil when the call is unavailable, so callers fall back to the
/// dynamic store.
enum DNSConfiguration {
    struct Resolver: Hashable {
        var domain: String?          // nil = the default resolver
        var nameservers: [String]
        var port: Int
        var searchDomains: [String]
        var interface: String?
        var order: UInt32
        var options: String?
        var flags: UInt32
        var scoped: Bool             // from the scoped list (bound to one interface)

        /// mDNS (Bonjour) scopes like `local` and link-local reverse zones.
        var isMulticast: Bool { (options ?? "").contains("mdns") }
        /// DNS_RESOLVER_FLAGS_SUPPLEMENTAL (0x4000): added by a VPN or app on top
        /// of the network's own resolvers.
        var isSupplemental: Bool { flags & 0x4000 != 0 }
    }

    private typealias Copy = @convention(c) () -> UnsafeMutableRawPointer?
    private typealias Free = @convention(c) (UnsafeMutableRawPointer?) -> Void

    static func current() -> [Resolver]? {
        guard let h = dlopen(nil, RTLD_NOW),
              let c = dlsym(h, "dns_configuration_copy"),
              let f = dlsym(h, "dns_configuration_free") else { return nil }
        let copy = unsafeBitCast(c, to: Copy.self)
        let free = unsafeBitCast(f, to: Free.self)
        guard let cfg = copy() else { return nil }
        defer { free(cfg) }

        // dns_config_t, pack(4): n_resolver@0, resolver@4, n_scoped@12, scoped@16.
        var out: [Resolver] = []
        out += resolvers(count: cfg.load(fromByteOffset: 0, as: Int32.self), list: loadPtr(cfg, 4), scoped: false)
        out += resolvers(count: cfg.load(fromByteOffset: 12, as: Int32.self), list: loadPtr(cfg, 16), scoped: true)
        return out
    }

    private static func resolvers(count: Int32, list: UnsafeRawPointer?, scoped: Bool) -> [Resolver] {
        guard count > 0, count < 256, let list else { return [] }
        return (0..<Int(count)).compactMap { i in
            loadPtr(list, i * 8).map { resolver($0, scoped: scoped) }
        }
    }

    // dns_resolver_t, pack(4), 64-bit offsets:
    //  0 domain  8 n_nameserver  12 nameserver  20 port  24 n_search  28 search
    //  36 n_sortaddr  40 sortaddr  48 options  56 timeout  60 search_order
    //  64 if_index  68 flags  72 reach_flags  76 service_identifier  80 cid  88 if_name
    private static func resolver(_ r: UnsafeRawPointer, scoped: Bool) -> Resolver {
        let nNS = Int(r.loadUnaligned(fromByteOffset: 8, as: Int32.self))
        var ns: [String] = []
        if nNS > 0, nNS < 64, let arr = loadPtr(r, 12) {
            for i in 0..<nNS {
                if let sa = loadPtr(arr, i * 8), let s = address(sa) { ns.append(s) }
            }
        }
        let nSearch = Int(r.loadUnaligned(fromByteOffset: 24, as: Int32.self))
        var search: [String] = []
        if nSearch > 0, nSearch < 64, let arr = loadPtr(r, 28) {
            for i in 0..<nSearch { if let s = string(loadPtr(arr, i * 8)) { search.append(s) } }
        }
        let ifIndex = r.loadUnaligned(fromByteOffset: 64, as: UInt32.self)
        var ifName = string(loadPtr(r, 88))
        if ifName == nil, ifIndex != 0 {
            var buf = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
            if if_indextoname(ifIndex, &buf) != nil { ifName = String(cString: buf) }
        }
        return Resolver(
            domain: string(loadPtr(r, 0)),
            nameservers: ns,
            port: Int(r.loadUnaligned(fromByteOffset: 20, as: UInt16.self)),
            searchDomains: search,
            interface: ifName,
            order: r.loadUnaligned(fromByteOffset: 60, as: UInt32.self),
            options: string(loadPtr(r, 48)),
            flags: r.loadUnaligned(fromByteOffset: 68, as: UInt32.self),
            scoped: scoped
        )
    }

    private static func loadPtr(_ base: UnsafeRawPointer, _ offset: Int) -> UnsafeRawPointer? {
        UnsafeRawPointer(bitPattern: base.loadUnaligned(fromByteOffset: offset, as: UInt.self))
    }

    private static func string(_ p: UnsafeRawPointer?) -> String? {
        guard let p else { return nil }
        let s = String(cString: p.assumingMemoryBound(to: CChar.self))
        return s.isEmpty ? nil : s
    }

    private static func address(_ sa: UnsafeRawPointer) -> String? {
        let family = sa.load(fromByteOffset: 1, as: UInt8.self)
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        switch Int32(family) {
        case AF_INET:
            var a = sa.loadUnaligned(fromByteOffset: 4, as: in_addr.self)
            return inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count)).map { _ in String(cString: buf) }
        case AF_INET6:
            var a = sa.loadUnaligned(fromByteOffset: 8, as: in6_addr.self)
            return inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count)).map { _ in String(cString: buf) }
        default:
            return nil
        }
    }
}

/// Human names for network interfaces: "Wi-Fi", "Ethernet", "VPN tunnel".
enum InterfaceNames {
    static func display(_ bsd: String?) -> String? {
        guard let bsd else { return nil }
        if bsd.hasPrefix("utun") || bsd.hasPrefix("ipsec") || bsd.hasPrefix("ppp") || bsd.hasPrefix("tun") { return "VPN tunnel" }
        if let all = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] {
            for i in all where (SCNetworkInterfaceGetBSDName(i) as String?) == bsd {
                if let name = SCNetworkInterfaceGetLocalizedDisplayName(i) as String? { return name }
            }
        }
        if bsd.hasPrefix("lo") { return "loopback" }
        return nil
    }
}

/// What this Mac does with a name: which resolvers, in order, and why.
struct MacDNSPlan {
    var defaults: [DNSConfiguration.Resolver]       // asked for everything else, in order
    var splitRules: [DNSConfiguration.Resolver]     // only for names under `domain`
    var multicast: [DNSConfiguration.Resolver]      // Bonjour scopes
    var scoped: [DNSConfiguration.Resolver]         // per-interface view

    init(_ all: [DNSConfiguration.Resolver]) {
        let main = all.filter { !$0.scoped }.sorted { $0.order < $1.order }
        defaults = main.filter { $0.domain == nil && !$0.isMulticast && !$0.nameservers.isEmpty }
        splitRules = main.filter { $0.domain != nil && !$0.isMulticast && !$0.nameservers.isEmpty }
        multicast = main.filter(\.isMulticast)
        scoped = all.filter(\.scoped)
    }

    /// The interface a nameserver is reached over, from the scoped list.
    func interface(for ns: String) -> String? {
        scoped.first { $0.nameservers.contains(ns) }?.interface
    }

    func describe(_ ns: String) -> String {
        guard let i = interface(for: ns) else { return ns }
        return "\(ns) (\(InterfaceNames.display(i) ?? i), \(i))"
    }

    /// The resolver macOS would use for a name: the most specific split rule
    /// or Bonjour scope that matches, otherwise the first default.
    func resolver(for name: String) -> (resolver: DNSConfiguration.Resolver, why: String)? {
        let n = name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let candidates = (splitRules + multicast).filter { r in
            guard let d = r.domain?.lowercased() else { return false }
            return n == d || n.hasSuffix("." + d)
        }
        if let best = candidates.max(by: { ($0.domain ?? "").count < ($1.domain ?? "").count }) {
            let why = best.isMulticast ? ".\(best.domain!) names never go to a DNS server" : "a rule, usually from a VPN, sends every domain ending in \(best.domain!) here"
            return (best, why)
        }
        if let d = defaults.first { return (d, "it comes first for all domains") }
        return nil
    }
}

/// Keeps the resolver configuration current: re-reads it whenever the
/// system's DNS settings change (a VPN connects, the network switches).
@MainActor
final class MacDNSMonitor: ObservableObject {
    @Published private(set) var plan = MacDNSPlan([])
    @Published private(set) var available = true
    @Published private(set) var changedAt: Date?
    private var store: SCDynamicStore?

    init() {
        reload(initial: true)
        // The store does not retain the monitor. The app has one, owned by
        // AppModel for as long as the app runs, so the callback never sees a
        // dead pointer.
        var ctx = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            let me = Unmanaged<MacDNSMonitor>.fromOpaque(info).takeUnretainedValue()
            Task { @MainActor in me.reload(initial: false) }
        }
        guard let store = SCDynamicStoreCreate(nil, "Nordyg DNS monitor" as CFString, callback, &ctx) else { return }
        SCDynamicStoreSetNotificationKeys(store, nil, ["State:/Network/Global/DNS", "State:/Network/Service/.*/DNS"] as CFArray)
        if let src = SCDynamicStoreCreateRunLoopSource(nil, store, 0) {
            CFRunLoopAddSource(CFRunLoopGetMain(), src, .commonModes)
        }
        self.store = store
    }

    func reload(initial: Bool) {
        guard let all = DNSConfiguration.current() else { available = false; return }
        let next = MacDNSPlan(all)
        if !initial, next.defaults != plan.defaults || next.splitRules != plan.splitRules { changedAt = Date() }
        plan = next
    }
}
