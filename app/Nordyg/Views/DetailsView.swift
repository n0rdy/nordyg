import SwiftUI

struct DetailsView: View {
    var result: QueryResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Section2("Header") {
                    KV("Question", "\(result.questionSent.name) \(result.questionSent.qclass ?? "IN") \(result.questionSent.type)")
                    KV("Rcode", result.message.rcode)
                    KV("Opcode", result.message.opcode)
                    KV("ID", "\(result.message.id)")
                    KV("Flags", result.message.flags.set.joined(separator: " "))
                    KV("Sections", "answer \(result.message.answer.count), authority \(result.message.authority.count), additional \(result.message.additional.count)")
                    KV("Size", "\(result.message.sizeBytes) bytes")
                }
                if let e = result.message.edns {
                    Section2("EDNS") {
                        KV("Version", "\(e.version)")
                        KV("UDP size", "\(e.udpSize)")
                        KV("DO", e.dnssecOk ? "set" : "clear")
                        KV("Extended rcode", "\(e.extendedRcode)")
                        ForEach(Array(e.options.enumerated()), id: \.offset) { _, o in
                            if let ede = o.ede {
                                KV("EDE \(ede.infoCode)", "\(ede.purpose)\(ede.extraText.isEmpty ? "" : ": " + ede.extraText)")
                            } else if let n = o.nsid {
                                KV("NSID", n.text)
                            } else {
                                KV(o.name, o.data.isEmpty ? "(present)" : o.data)
                            }
                        }
                    }
                } else {
                    Section2("EDNS") { KV("OPT", "none in response") }
                }
                ExchangeSection(exchange: result.exchange)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct ExchangeSection: View {
    var exchange: Exchange
    var body: some View {
        Section2("Wire") {
            KV("Endpoint", exchange.endpoint.summary)
            KV("Protocol", exchange.protocol + (exchange.truncatedRetry ? " (retried over TCP after truncation)" : ""))
            KV("Round trip", String(format: "%.2f ms", exchange.rttMs))
            KV("Started", exchange.startedAt)
            if let h = exchange.http {
                KV("HTTP", "\(h.version) \(h.status) \(h.contentType)")
            }
            if let t = exchange.tls {
                KV("TLS", "\(t.version), \(t.cipherSuite), ALPN \(t.alpn.isEmpty ? "none" : t.alpn), handshake \(String(format: "%.1f", t.handshakeMs)) ms")
                KV("Server name", t.serverName)
                if let c = t.certificate {
                    KV("Certificate", c.subject)
                    KV("Issuer", c.issuer)
                    KV("Valid", "\(c.notBefore) → \(c.notAfter)")
                    KV("SANs", c.dnsNames.joined(separator: ", "))
                    KV("SHA-256", c.sha256)
                }
            }
        }
    }
}

struct Section2<Content: View>: View {
    var title: String
    @ViewBuilder var content: Content
    init(_ title: String, @ViewBuilder content: () -> Content) { self.title = title; self.content = content() }
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) { content }
        }
    }
}

struct KV: View {
    var key: String
    var value: String
    init(_ key: String, _ value: String) { self.key = key; self.value = value }
    var body: some View {
        GridRow {
            Text(key).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(value).font(.system(.body, design: .monospaced)).textSelection(.enabled)
        }
    }
}
