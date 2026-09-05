import AppKit

/// Links that the About panel and the Help menu point at. One place, so the
/// app never disagrees with itself about where things live.
enum Links {
    static let docs = URL(string: "https://nordyg.com/docs/")!
    static let source = URL(string: "https://github.com/n0rdy/nordyg")!
    static let discussions = URL(string: "https://github.com/n0rdy/nordyg/discussions/categories/bugs")!
    static let blog = URL(string: "https://n0rdy.foo")!
    static let x = URL(string: "https://x.com/_n0rdy_")!
    static let licence = URL(string: "https://github.com/n0rdy/nordyg/blob/main/LICENSE")!
}

/// The standard macOS About panel with a credits block that carries the
/// maker's links and the source offer the AGPL asks for.
enum AboutPanel {
    static func show() {
        let credits = NSMutableAttributedString()
        let body: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
            .foregroundColor: NSColor.labelColor,
        ]
        func line(_ text: String, link: URL? = nil, newline: Bool = true) {
            var attrs = body
            if let link { attrs[.link] = link }
            credits.append(NSAttributedString(string: text, attributes: attrs))
            if newline { credits.append(NSAttributedString(string: "\n", attributes: body)) }
        }
        line("A native DNS client for macOS.")
        line("")
        line("Made by Myko Nordy")
        line("x.com/_n0rdy_", link: Links.x, newline: false)
        line("  ·  ", newline: false)
        line("n0rdy.foo", link: Links.blog)
        line("")
        line("Source code", link: Links.source, newline: false)
        line("  ·  ", newline: false)
        line("Questions and bugs", link: Links.discussions, newline: false)
        line("  ·  ", newline: false)
        line("AGPL-3.0", link: Links.licence)

        let style = NSMutableParagraphStyle()
        style.alignment = .center
        credits.addAttribute(.paragraphStyle, value: style, range: NSRange(location: 0, length: credits.length))

        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits])
    }
}
