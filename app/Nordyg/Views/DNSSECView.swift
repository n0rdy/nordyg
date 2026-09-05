import SwiftUI

struct DNSSECView: View {
    var result: DNSSECResult?
    @State private var selected: Int?

    var body: some View {
        if let r = result {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: DNSSECStyle.icon(r.status))
                            .font(.system(size: 28))
                            .foregroundStyle(DNSSECStyle.color(r.status))
                            .frame(width: 40)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(DNSSECWording.label(r.status).capitalizedFirst).font(.title2.weight(.semibold))
                            Text(DNSSECWording.headline(r)).textSelection(.enabled)
                            if let detail = DNSSECWording.detail(r) {
                                Text(detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                        }
                        Spacer()
                        if let a = r.trustAnchor {
                            VStack(alignment: .trailing, spacing: 2) {
                                Text("trust anchor").font(.caption).foregroundStyle(.secondary)
                                Text("KSK \(a.keyTag) · \(a.algorithmName)").font(.system(.callout, design: .monospaced))
                            }
                        }
                    }

                    Text("Chain of trust").font(.headline)
                    ChainStrip(chain: r.chain, selected: $selected)

                    if let i = selected ?? r.chain.indices.last, r.chain.indices.contains(i) {
                        LinkCard(link: r.chain[i])
                    }

                    if !r.answerSignatures.isEmpty {
                        Text("Answer signatures").font(.headline)
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(Array(r.answerSignatures.enumerated()), id: \.offset) { _, s in SignatureRow(sig: s) }
                        }
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            ContentUnavailableView("Validation was off", systemImage: "lock.slash", description: Text("Turn on “Validate DNSSEC” and run again to see the chain of trust."))
        }
    }
}

/// The chain as connected nodes: root on the left, the queried zone on the
/// right, each coloured by its verdict.
struct ChainStrip: View {
    var chain: [DNSSECLink]
    @Binding var selected: Int?

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 0) {
                ForEach(Array(chain.enumerated()), id: \.offset) { i, link in
                    ChainNode(link: link, isSelected: (selected ?? chain.count - 1) == i) { selected = i }
                    if i < chain.count - 1 {
                        Rectangle()
                            .fill(DNSSECStyle.color(chain[i + 1].status).opacity(0.5))
                            .frame(width: 40, height: 2)
                            .offset(y: -18)
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }
}

struct ChainNode: View {
    var link: DNSSECLink
    var isSelected: Bool
    var action: () -> Void

    var body: some View {
        let color = DNSSECStyle.color(link.status)
        Button(action: action) {
            VStack(spacing: 6) {
                ZStack {
                    Circle().fill(color.opacity(0.18)).frame(width: 46, height: 46)
                    Circle().stroke(color, lineWidth: isSelected ? 3 : 1.5).frame(width: 46, height: 46)
                    Image(systemName: DNSSECStyle.icon(link.status)).foregroundStyle(color).font(.system(size: 18))
                }
                Text(link.zone == "." ? "root" : prose(link.zone)).font(.system(.callout, design: .monospaced).weight(.semibold)).lineLimit(1)
                Text(DNSSECWording.label(link.status)).font(.caption).foregroundStyle(.secondary)
            }
            .frame(minWidth: 90)
        }
        .buttonStyle(.plain)
    }
}

struct LinkCard: View {
    var link: DNSSECLink

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(link.zone == "." ? "root zone" : prose(link.zone)).font(.system(.body, design: .monospaced).weight(.semibold))
                StatusBadge(status: link.status)
                Spacer()
            }
            if let reason = link.reason, !reason.isEmpty {
                Text(reason).font(.callout).foregroundStyle(link.status == "bogus" ? Color.red : Color.secondary).textSelection(.enabled)
            }
            if link.dnskeys.isEmpty && link.ds.isEmpty && link.signatures.isEmpty {
                Text("No keys at this level.").font(.callout).foregroundStyle(.secondary)
            }
            if !link.dnskeys.isEmpty {
                Text("Keys").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(Array(link.dnskeys.enumerated()), id: \.offset) { _, k in
                    HStack(spacing: 8) {
                        Pill(text: k.role.uppercased(), color: k.role == "ksk" ? .yellow : .secondary, mono: true)
                        Text("tag \(k.keyTag) · \(k.algorithmName)").font(.system(.callout, design: .monospaced))
                        if k.trustAnchor == true { Pill(text: "trust anchor", icon: "anchor", color: .green) }
                    }
                }
            }
            if !link.ds.isEmpty {
                Text("DS from the parent").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(Array(link.ds.enumerated()), id: \.offset) { _, d in
                    HStack(spacing: 8) {
                        Image(systemName: d.matchesDnskey ? "checkmark.circle.fill" : "xmark.circle.fill").foregroundStyle(d.matchesDnskey ? Color.green : Color.red)
                        Text("tag \(d.keyTag) · alg \(d.algorithm) · digest \(d.digestType)").font(.system(.callout, design: .monospaced))
                        Text(d.matchesDnskey ? "matches a key" : "matches nothing").font(.callout).foregroundStyle(d.matchesDnskey ? Color.secondary : Color.red)
                    }
                }
            }
            if !link.signatures.isEmpty {
                Text("Signatures").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(Array(link.signatures.enumerated()), id: \.offset) { _, s in SignatureRow(sig: s) }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

struct SignatureRow: View {
    var sig: DNSSECSignature
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: sig.valid ? "checkmark.seal.fill" : "xmark.seal.fill").foregroundStyle(sig.valid ? Color.green : Color.red)
            TypeBadge(type: sig.typeCovered)
            Text("\(prose(sig.name)) signed by \(prose(sig.signer)) key \(sig.keyTag), \(expires)")
            if let e = sig.error { Text("— \(e)").foregroundStyle(.red) }
        }
        .font(.system(.callout, design: .monospaced))
        .textSelection(.enabled)
    }
    var expires: String {
        let days = Double(sig.expiresInMs) / 86_400_000
        if days < 0 { return "expired \(sig.expiration)" }
        if days < 1 { return String(format: "expires in %.0f h", days * 24) }
        return String(format: "expires in %.0f d", days)
    }
}
