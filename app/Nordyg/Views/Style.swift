import AppKit
import SwiftUI

/// Semantic colour for record types, the way database tools colour column
/// types. Related types share a hue so a table reads at a glance.
enum TypeStyle {
    static func color(_ type: String) -> Color {
        switch type.uppercased() {
        case "A": return .blue
        case "AAAA": return .teal
        case "CNAME", "DNAME": return .gray
        case "MX": return .purple
        case "TXT", "SPF": return .orange
        case "NS": return .green
        case "SOA": return .brown
        case "PTR": return .mint
        case "SRV", "NAPTR", "TLSA", "SSHFP": return .cyan
        case "CAA": return .pink
        case "HTTPS", "SVCB": return .indigo
        case "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "CDS", "CDNSKEY": return .yellow
        default: return .secondary
        }
    }

    /// The type's colour for text. Several system colours (yellow, orange,
    /// mint, cyan) are too bright to read on a light background, so in light
    /// mode the colour is darkened step by step until it reaches 4.5:1 against
    /// its own badge (a 16% tint over the window). Dark mode keeps it as is.
    static func ink(_ type: String) -> Color {
        let tint = color(type)
        guard tint != .secondary else { return .secondary }
        let base = NSColor(tint)
        return Color(nsColor: NSColor(name: nil) { appearance in
            guard appearance.bestMatch(from: [.aqua, .darkAqua]) == .aqua else { return base }
            var light = base
            appearance.performAsCurrentDrawingAppearance {
                light = base.usingColorSpace(.sRGB) ?? base
            }
            let badge = NSColor.white.blended(withFraction: 0.16, of: light) ?? .white
            var ink = light
            for step in stride(from: 0.0, through: 0.85, by: 0.05) {
                ink = light.blended(withFraction: step, of: .black) ?? light
                if contrast(ink, badge) >= 4.5 { break }
            }
            return ink
        })
    }

    /// WCAG contrast ratio of two sRGB colours.
    private static func contrast(_ a: NSColor, _ b: NSColor) -> Double {
        func lum(_ c: NSColor) -> Double {
            guard let c = c.usingColorSpace(.sRGB) else { return 0 }
            func lin(_ v: CGFloat) -> Double {
                let v = Double(v)
                return v <= 0.03928 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4)
            }
            return 0.2126 * lin(c.redComponent) + 0.7152 * lin(c.greenComponent) + 0.0722 * lin(c.blueComponent)
        }
        let (x, y) = (lum(a), lum(b))
        return (max(x, y) + 0.05) / (min(x, y) + 0.05)
    }
}

struct TypeBadge: View {
    var type: String
    var body: some View {
        Text(type)
            .help(Glossary.recordType(type))
            .font(.system(.caption, design: .monospaced).weight(.bold))
            .foregroundStyle(TypeStyle.ink(type))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .frame(minWidth: 44)
            .background(TypeStyle.color(type).opacity(0.16))
            .clipShape(RoundedRectangle(cornerRadius: 5))
    }
}

/// A compact status chip.
struct Pill: View {
    var text: String
    var icon: String?
    var color: Color = .secondary
    var mono = false
    var help: String?

    var body: some View {
        HStack(spacing: 4) {
            if let icon { Image(systemName: icon).foregroundStyle(color) }
            Text(text)
                .font(mono ? .system(.caption, design: .monospaced).weight(.semibold) : .caption.weight(.semibold))
        }
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(color.opacity(0.14))
        .clipShape(Capsule())
        .help(help ?? "")
    }
}

/// Plain metadata in a status strip: quiet monospaced text, no capsule.
/// Capsules are kept for verdicts and exceptions, so those stand out.
struct Meta: View {
    var text: String
    var help: String?
    var body: some View {
        Text(text)
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.secondary)
            .help(help ?? "")
    }
}

/// Separator between quiet metadata items.
struct Dot: View {
    var body: some View { Text("·").foregroundStyle(.tertiary) }
}

/// A slim row holding the view switcher for a result, kept apart from the
/// pill strip so neither has to fit the other.
struct TabRow<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        HStack {
            content
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .tint(.accentColor) // the default grey selection is too faint to spot
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }
}

/// The row of pills under the command bar summarising a result.
struct StatusStrip<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) { content }
                .padding(.horizontal, 12).padding(.vertical, 7)
        }
        .background(.bar)
    }
}

enum Rcode {
    static func color(_ rcode: String) -> Color {
        switch rcode {
        case "NOERROR": return .green
        case "NXDOMAIN": return .orange
        default: return .red
        }
    }
}

struct RcodeBadge: View {
    var rcode: String
    var body: some View { Pill(text: rcode, color: Rcode.color(rcode), mono: true, help: Glossary.rcode(rcode)) }
}

enum DNSSECStyle {
    static func color(_ status: String) -> Color {
        switch status {
        case "secure": return .green
        case "insecure": return .gray
        case "bogus": return .red
        default: return .orange
        }
    }
    static func icon(_ status: String) -> String {
        switch status {
        case "secure": return "lock.fill"
        case "insecure": return "lock.open"
        case "bogus": return "xmark.shield.fill"
        default: return "questionmark.circle"
        }
    }
}

struct StatusBadge: View {
    var status: String
    var body: some View {
        Pill(text: DNSSECWording.label(status), icon: DNSSECStyle.icon(status), color: DNSSECStyle.color(status), help: Glossary.dnssec(status))
    }
}

/// Scrolls both ways with its content pinned to the top-left. A two-axis
/// ScrollView on its own centres content smaller than itself.
struct PinnedScroll<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        GeometryReader { geo in
            ScrollView([.vertical, .horizontal]) {
                content.frame(minWidth: geo.size.width, minHeight: geo.size.height, alignment: .topLeading)
            }
        }
    }
}

extension View {
    /// Card chrome: full width, 12 pt inset, 8 pt corners.
    func card(fill: Color = Color.secondary.opacity(0.06)) -> some View {
        padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(fill)
            .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    /// A block set off inside a card or row: 8 pt inset, 6 pt corners.
    func inset(fill: Color = Color.secondary.opacity(0.06), fullWidth: Bool = false) -> some View {
        padding(8)
            .frame(maxWidth: fullWidth ? .infinity : nil, alignment: .leading)
            .background(fill)
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

func severityIcon(_ s: String) -> String {
    switch s { case "error": return "xmark.octagon.fill"; case "warning": return "exclamationmark.triangle.fill"; default: return "info.circle" }
}

func severityColor(_ s: String) -> Color {
    switch s { case "error": return .red; case "warning": return .orange; default: return .secondary }
}

/// Reduced-motion aware animation for result changes.
struct ResultAnimation: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduce
    var value: Int
    func body(content: Content) -> some View {
        content.animation(reduce ? nil : .easeOut(duration: 0.18), value: value)
    }
}

enum VerdictStyle {
    static func color(_ status: String) -> Color {
        switch status {
        case "ok": return .green
        case "warn": return .orange
        case "fail": return .red
        default: return .secondary
        }
    }
    static func icon(_ status: String) -> String {
        switch status {
        case "ok": return "checkmark.circle.fill"
        case "warn": return "exclamationmark.triangle.fill"
        case "fail": return "xmark.octagon.fill"
        default: return "info.circle"
        }
    }
    static func label(_ status: String) -> String {
        switch status {
        case "ok": return "OK"
        case "warn": return "warning"
        case "fail": return "failing"
        default: return "info"
        }
    }
}

struct VerdictPill: View {
    var verdict: Verdict
    var body: some View {
        Pill(text: VerdictStyle.label(verdict.status), icon: VerdictStyle.icon(verdict.status), color: VerdictStyle.color(verdict.status), help: verdict.message)
    }
}
