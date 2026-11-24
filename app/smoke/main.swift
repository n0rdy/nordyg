// Bridge smoke harness: exercises the C surface through the app's own bridge
// wrapper and Codable models (compiled in from app/Nordyg/Core), so the JSON
// the core emits is proven to decode into the types the views use.
// No network by default; NORDYG_SMOKE_NET=1 adds live checks. Run: make smoke.

import Foundation
import NordygCore

func check(_ cond: Bool, _ msg: String) {
    if !cond { print("FAIL: \(msg)"); exit(1) }
    print("ok   \(msg)")
}

@main
struct Smoke {
    static func main() async throws {
        let core = Core.shared

        // 1. ping: bridge round trip and op discovery through the typed wrapper.
        let ping: PingResult = try await core.call("ping")
        check(ping.contractVersion == 1 && ping.ops.contains("query") && ping.ops.contains("trace"), "ping decodes (version \(ping.version), ops \(ping.ops.count))")

        // 2. presets decode into the model, including the NextDNS placeholder flag.
        let presets: PresetsResult = try await core.call("presets")
        check(presets.presets.count == 6, "presets decode (\(presets.presets.count))")
        check(presets.presets.first { $0.id == "nextdns" }?.endpoints.allSatisfy(\.needsPlaceholder) == true, "placeholder endpoints are flagged")

        // 3. error path: unknown op arrives as a typed CoreError.
        do {
            let _: PingResult = try await core.call("no-such-op")
            check(false, "unknown op should throw")
        } catch let e as CoreError {
            check(e.code == "unknown_op", "unknown op is CoreError(\(e.code))")
        }

        // 4. bad params arrive as bad_request with the message intact.
        do {
            let _: QueryResult = try await core.call("query", QueryParams(question: Question(name: "", type: "A", qclass: nil), endpoint: Endpoint(transport: "udp", address: "127.0.0.1:1", tlsName: nil, url: nil, method: nil, label: nil), options: Options(), validate: false, bootstrap: []))
            check(false, "empty name should throw")
        } catch let e as CoreError {
            check(e.code == "bad_request" && e.message.contains("name"), "validation error: \(e.message)")
        }

        // 5. malformed JSON straight into the C function still returns an envelope.
        let mal = "{".withCString { NordygQuery($0) }!
        let malText = String(cString: mal)
        NordygFree(mal)
        check(malText.contains("bad_request"), "malformed JSON is a structured error")

        // 6. cancellation: a query to a black-hole address is cancelled from Swift.
        let task = Task { () -> String in
            do {
                let _: QueryResult = try await core.call("query", QueryParams(question: Question(name: "example.test", type: "A", qclass: nil), endpoint: Endpoint(transport: "tcp", address: "192.0.2.1:53", tlsName: nil, url: nil, method: nil, label: nil), options: Options(timeoutMs: 20000), validate: false, bootstrap: []))
                return "completed"
            } catch let e as CoreError { return e.code } catch { return "swift-cancel" }
        }
        try await Task.sleep(nanoseconds: 200_000_000)
        task.cancel()
        let outcome = await task.value
        check(outcome == "cancelled" || outcome == "swift-cancel", "cancel aborts an in-flight query (\(outcome))")

        // 7. export needs no network and round-trips Options encoding.
        let exp: ExportResult = try await core.call("export", ExportParams(question: Question(name: "example.com", type: "MX", qclass: nil), endpoint: Endpoint(transport: "dot", address: "9.9.9.9:853", tlsName: "dns.quad9.net", url: nil, method: nil, label: nil), options: Options(dnssecOk: false, timeoutMs: 2000), format: "dig"))
        check(exp.command == "dig @9.9.9.9 example.com MX +tls +tls-hostname=dns.quad9.net +timeout=2", "export encodes options: \(exp.command)")

        // 7b. the app's ExportSupport table matches what the core accepts.
        let sample: [String: Endpoint] = [
            "udp": Endpoint(transport: "udp", address: "9.9.9.9:53", tlsName: nil, url: nil, method: nil, label: nil),
            "tcp": Endpoint(transport: "tcp", address: "9.9.9.9:53", tlsName: nil, url: nil, method: nil, label: nil),
            "dot": Endpoint(transport: "dot", address: "9.9.9.9:853", tlsName: "dns.quad9.net", url: nil, method: nil, label: nil),
            "doh": Endpoint(transport: "doh", address: nil, tlsName: nil, url: "https://dns.quad9.net/dns-query", method: nil, label: nil),
            "doq": Endpoint(transport: "doq", address: "94.140.14.14:853", tlsName: "dns.adguard-dns.com", url: nil, method: nil, label: nil),
        ]
        var mismatches: [String] = []
        for (transport, ep) in sample.sorted(by: { $0.key < $1.key }) {
            for f in ExportSupport.formats {
                var accepted = true
                do {
                    let _: ExportResult = try await core.call("export", ExportParams(question: Question(name: "example.com", type: "A", qclass: nil), endpoint: ep, options: Options(), format: f))
                } catch let e as CoreError where e.code == "export_unsupported" { accepted = false }
                if accepted != ExportSupport.can(f, over: transport) { mismatches.append("\(f) over \(transport)") }
            }
        }
        check(mismatches.isEmpty, "Copy menu formats match the core (\(mismatches.isEmpty ? "20 pairs" : mismatches.joined(separator: ", ")))")

        if ProcessInfo.processInfo.environment["NORDYG_SMOKE_NET"] == "1" {
            let cf = Endpoint(transport: "dot", address: "1.1.1.1:853", tlsName: "cloudflare-dns.com", url: nil, method: nil, label: "Cloudflare DoT")

            // 8. full query result decodes, with DNSSEC validated against the live root.
            let q: QueryResult = try await core.call("query", QueryParams(question: Question(name: "cloudflare.com", type: "A", qclass: nil), endpoint: cf, options: Options(), validate: true, bootstrap: []))
            check(q.message.rcode == "NOERROR" && !q.message.answer.isEmpty && q.exchange.tls?.certificate != nil, "live DoT query decodes (\(q.message.answer.count) answers, \(q.exchange.rttMs) ms)")
            check(q.dnssec?.status == "secure" && q.dnssec?.chain.count == 3, "cloudflare.com validates secure (\(q.dnssec?.status ?? "-") \(q.dnssec?.reason ?? ""))")
            for l in q.dnssec?.chain ?? [] { print("     \(l.zone) \(l.status) \(l.dnskeys.count) keys") }

            // 9. TXT decoding reaches the model as JSONValue.
            let txt: QueryResult = try await core.call("query", QueryParams(question: Question(name: "cloudflare.com", type: "TXT", qclass: nil), endpoint: cf, options: Options(), validate: false, bootstrap: []))
            let spf = txt.message.answer.first { $0.decoded?["kind"]?.stringValue == "spf" }
            check(spf != nil, "SPF record decoded (\(spf?.decoded?["lookup_count"]?.display ?? "?") lookups)")

            // 10. compare groups decode.
            let cmp: CompareResult = try await core.call("compare", CompareParams(question: Question(name: "example.com", type: "A", qclass: nil), endpoints: [Endpoint(transport: "udp", address: "1.1.1.1:53", tlsName: nil, url: nil, method: nil, label: "Cloudflare"), Endpoint(transport: "udp", address: "8.8.8.8:53", tlsName: nil, url: nil, method: nil, label: "Google")], options: Options(), bootstrap: []))
            check(cmp.results.count == 2 && !cmp.groups.isEmpty, "compare decodes (consistent=\(cmp.consistent), \(cmp.groups.count) groups)")

            // 11. trace decodes with referrals and validation.
            let tr: TraceResult = try await core.call("trace", TraceParams(question: Question(name: "cloudflare.com", type: "A", qclass: nil), options: Options(), validate: true, bootstrap: [], rootHints: nil))
            check(tr.hops.count >= 3 && tr.hops[0].referral != nil && tr.dnssec?.status == "secure", "trace decodes (\(tr.hops.count) hops, \(tr.dnssec?.status ?? "-"))")
            for h in tr.hops { print("     \(h.zone) via \(h.server.name) \(h.server.address)") }

            // 12. system resolvers are discoverable from the sandbox-safe API.
            let sys = SystemResolvers.endpoints()
            check(!sys.isEmpty, "system resolvers found: \(sys.map { $0.address ?? "?" }.joined(separator: " "))")

            // 13b. email report for a real, well-configured mail domain.
            let em: EmailResult = try await core.call("email", EmailParams(domain: "cloudflare.com", endpoint: cf, options: Options(), bootstrap: [], extraDkimSelectors: []))
            check(em.mx.verdict.status != "fail" && em.spf.verdict.status != "fail" && em.dmarc.verdict.status == "ok" && em.spf.totalLookups > 0,
                  "email report decodes (overall \(em.overall.status): mx \(em.mx.verdict.status), spf \(em.spf.totalLookups) lookups \(em.spf.verdict.status), dkim \(em.dkim.verdict.status), dmarc \(em.dmarc.verdict.status), mta-sts \(em.mtaSts.verdict.status), bimi \(em.bimi.verdict.status), dnsbl \(em.dnsbl.verdict.status))")
            print("     \(em.overall.message)")
            let dn: EmailResult = try await core.call("email", EmailParams(domain: "posteo.de", endpoint: cf, options: Options(), bootstrap: [], extraDkimSelectors: []))
            check(dn.dane.mxStatus == "secure" && !dn.dane.hosts.isEmpty && dn.dane.hosts.allSatisfy { $0.status == "secure" && !$0.tlsa.isEmpty } && dn.dane.verdict.status == "ok",
                  "dane decodes for posteo.de (\(dn.dane.verdict.message))")
            print("     transport: \(dn.transport.status) \(dn.transport.message)")

            // 13e. zone health from the real root servers, decoded through the Swift mirror.
            let hz: HealthResult = try await core.call("health", HealthParams(domain: "cloudflare.com", endpoint: cf, options: Options(), bootstrap: []))
            check(hz.zone == "cloudflare.com." && hz.delegation.verdict.status == "ok" && hz.nameservers.servers.contains { $0.authoritative } && hz.dnssec.status == "secure" && hz.soa.record != nil,
                  "health report decodes (overall \(hz.overall.status): \(hz.nameservers.servers.count) addresses, dnssec \(hz.dnssec.status), caa \(hz.caa.verdict.status))")
            print("     \(hz.overall.message)")
            for f in hz.https.findings { print("     https \(f.status): \(f.message)") }
            for h in hz.https.hosts { for sv in h.servers where !sv.skipped { print("     \(h.name) \(sv.ip) connected=\(sv.connected) \(sv.error ?? "")") } }
            check(hz.https.hosts.count == 2 && hz.https.verdict.status == "ok" && hz.https.hosts[0].servers.contains { $0.connected && $0.trusted && $0.revocationChecked },
                  "https card decodes (\(hz.https.verdict.message))")

            // 13d. registration data: RDAP for a gTLD, WHOIS fallback for a ccTLD without RDAP.
            let rd: RDAPResult = try await core.call("rdap", RDAPParams(domain: "example.com", endpoint: cf, options: Options(), bootstrap: []))
            check(rd.source == "rdap" && rd.found && rd.registrar.name != nil && rd.expires != nil && !rd.nameservers.isEmpty,
                  "rdap example.com: \(rd.registrar.name ?? "?") (IANA \(rd.registrar.ianaId ?? "?")), expires \(rd.expires ?? "?"), \(rd.status.count) status, ns \(rd.nameservers.count), bootstrap \(rd.bootstrapSource)")
            let wh: RDAPResult = try await core.call("rdap", RDAPParams(domain: "retrek.me", endpoint: cf, options: Options(), bootstrap: []))
            check(wh.found && !wh.nameservers.isEmpty,
                  "registry retrek.me via \(wh.source) \(wh.server): \(wh.registrar.name ?? "?"), expires \(wh.expires ?? "?"), ns \(wh.nameservers.joined(separator: " "))")

            // 13c. optional: full report for a domain of your choice.
            if let dom = ProcessInfo.processInfo.environment["NORDYG_SMOKE_MAIL_DOMAIN"], !dom.isEmpty {
                let r: EmailResult = try await core.call("email", EmailParams(domain: dom, endpoint: cf, options: Options(), bootstrap: [], extraDkimSelectors: []))
                print("     \(dom): overall \(r.overall.status) — \(r.overall.message)")
                for (n, v) in [("mx", r.mx.verdict), ("spf", r.spf.verdict), ("dkim", r.dkim.verdict), ("dmarc", r.dmarc.verdict), ("mta-sts", r.mtaSts.verdict), ("bimi", r.bimi.verdict), ("dnsbl", r.dnsbl.verdict)] {
                    print("       \(n): \(v.status) — \(v.message)")
                }
                for s in r.dkim.selectors where s.found { print("       dkim \(s.selector): \(s.decoded?["key_bits"]?.display ?? "?")-bit \(s.decoded?["key_type"]?.display ?? "")") }
            }

            // 13. the system resolver view (what other apps see) works.
            let seen = await SystemLookup.addresses(for: "cloudflare.com")
            check(!seen.isEmpty && !Set(seen).isDisjoint(with: Set(q.message.addresses)), "Mac's own resolver agrees: \(seen.joined(separator: " "))")
        }

        print("smoke passed")
    }
}
