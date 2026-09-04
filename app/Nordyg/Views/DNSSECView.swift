import SwiftUI

struct DNSSECView: View {
    var result: DNSSECResult?

    var body: some View {
        if let r = result {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .top, spacing: 10) {
                        StatusBadge(status: r.status)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(DNSSECWording.headline(r)).textSelection(.enabled)
                            if let detail = DNSSECWording.detail(r) {
                                Text(detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                        }
                        Spacer()
                        if let a = r.trustAnchor { Text("anchor: KSK \(a.keyTag) (\(a.algorithmName))").foregroundStyle(.secondary).font(.callout) }
                    }
                    Text("Chain of trust").font(.headline)
                    ForEach(Array(r.chain.enumerated()), id: \.offset) { i, link in
                        LinkView(link: link, isLast: i == r.chain.count - 1)
                    }
                    if !r.answerSignatures.isEmpty {
                        Text("Answer signatures").font(.headline).padding(.top, 6)
                        ForEach(Array(r.answerSignatures.enumerated()), id: \.offset) { _, s in SignatureRow(sig: s) }
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            VStack(spacing: 6) {
                Image(systemName: "lock.slash").font(.system(size: 32)).foregroundStyle(.tertiary)
                Text("Validation was off for this query. Turn on “Validate DNSSEC” and run again.").foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

struct LinkView: View {
    var link: DNSSECLink
    var isLast: Bool
    @State private var open = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(spacing: 0) {
                Circle().fill(StatusBadge(status: link.status).color).frame(width: 12, height: 12)
                if !isLast { Rectangle().fill(Color.secondary.opacity(0.3)).frame(width: 2).frame(maxHeight: .infinity) }
            }
            .frame(width: 12)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(link.zone).font(.system(.body, design: .monospaced).weight(.semibold))
                    Text(DNSSECWording.label(link.status)).foregroundStyle(.secondary)
                    Spacer()
                    Button(open ? "Hide" : "Keys") { open.toggle() }.buttonStyle(.link).font(.callout)
                }
                if let reason = link.reason, !reason.isEmpty {
                    Text(reason).font(.callout).foregroundStyle(link.status == "bogus" ? Color.red : Color.secondary).textSelection(.enabled)
                }
                Text(keySummary).font(.callout).foregroundStyle(.secondary)
                if open {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(link.dnskeys.enumerated()), id: \.offset) { _, k in
                            Text("DNSKEY \(k.keyTag) \(k.role.uppercased()) \(k.algorithmName)\(k.trustAnchor == true ? "  (trust anchor)" : "")")
                        }
                        ForEach(Array(link.ds.enumerated()), id: \.offset) { _, d in
                            Text("DS \(d.keyTag) alg \(d.algorithm) digest \(d.digestType)  \(d.matchesDnskey ? "matches a DNSKEY" : "matches nothing")")
                                .foregroundStyle(d.matchesDnskey ? Color.primary : Color.red)
                        }
                        ForEach(Array(link.signatures.enumerated()), id: \.offset) { _, s in SignatureRow(sig: s) }
                    }
                    .font(.system(.callout, design: .monospaced))
                    .padding(8)
                    .background(Color.secondary.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }
            .padding(.bottom, 12)
        }
    }

    var keySummary: String {
        let ksks = link.dnskeys.filter { $0.role == "ksk" }.count
        let zsks = link.dnskeys.filter { $0.role == "zsk" }.count
        var parts: [String] = []
        if ksks + zsks > 0 { parts.append("\(ksks) KSK, \(zsks) ZSK") }
        if !link.ds.isEmpty { parts.append("\(link.ds.count) DS") }
        parts.append("\(link.signatures.filter(\.valid).count)/\(link.signatures.count) signatures valid")
        return parts.joined(separator: " · ")
    }
}

struct SignatureRow: View {
    var sig: DNSSECSignature
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: sig.valid ? "checkmark.seal.fill" : "xmark.seal.fill").foregroundStyle(sig.valid ? .green : .red)
            Text("RRSIG \(sig.typeCovered) \(sig.name) by \(sig.signer) key \(sig.keyTag), expires \(expires)")
            if let e = sig.error { Text("— \(e)").foregroundStyle(.red) }
        }
        .font(.system(.callout, design: .monospaced))
        .textSelection(.enabled)
    }
    var expires: String {
        let days = Double(sig.expiresInMs) / 86_400_000
        if days < 0 { return "expired \(sig.expiration)" }
        if days < 1 { return String(format: "in %.0f h", days * 24) }
        return String(format: "in %.0f d", days)
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
            return "\(prose(zone)) is not signed with DNSSEC. \(proseZone(parent).capitalizedFirst) confirms there is no DS record, so there is nothing to validate. This is the normal state for most domains."
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

/// Names for prose: no trailing dot, and TLDs written as ".me" so they do
/// not read like words.
func prose(_ name: String) -> String {
    name == "." ? "the root" : String(name.hasSuffix(".") ? name.dropLast() : Substring(name))
}

func proseZone(_ zone: String) -> String {
    let bare = zone.hasSuffix(".") ? String(zone.dropLast()) : zone
    if bare.isEmpty { return "the root zone" }
    return bare.contains(".") ? "the zone \(bare)" : "the .\(bare) zone"
}

extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
