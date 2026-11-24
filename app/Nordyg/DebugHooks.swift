#if DEBUG
import AppKit
import SwiftUI

/// Debug-build remote control, so the UI can be reviewed without granting
/// any app Screen Recording permission: the app renders its own window,
/// which needs none, and does so even when the window is on another Space.
///
/// Commands arrive as distributed notifications named
/// `foo.n0rdy.nordyg.debug` whose object is the command string:
///
///     mode <query|compare|trace|email|registry|health>  (compare = Query with
///                          several resolvers)
///     several <on|off>     Query asks several resolvers
///     checklist <on|off>   open the several-resolvers checklist
///     drill <index|none>   open a compared resolver's full answer
///     name <text>          set the input field
///     run                  run the current mode
///     clear                clear the current tab
///     size <w> <h>         resize the window (content size, points)
///     history <mode|all>   filter the sidebar history
///     select <row|none>    select a row in the visible records table
///     type <TYPE>          record type token (A, MX, ALL, …)
///     resolver <text>      first resolver whose title or address contains text
///     compare <a, b, …>    Compare's resolver set: first endpoint whose title or
///                          summary contains each term; "unreachable" adds a
///                          custom UDP resolver at 192.0.2.1 that never answers
///     export <fmt>         write Copy as <fmt> to <container tmp>/nordyg-export.txt
///     tab <name>           result tab of the current mode (records, details,
///                          dnssec, raw; hops, final for Trace)
///     rerun <index>        re-run a history entry, as clicking it does
///     appearance <light|dark|system>  force the app's appearance (screenshots)
///     cards <open|auto|title>  open every report card's details on the next
///                          run, or only the card with that title
///     snapshot             write <container tmp>/nordyg-snapshot.png once idle
///     snapshot active      same, after bringing the window to the front, so
///                          accent colours show as in a focused window
///
/// Release builds compile none of this.
@MainActor
enum DebugHooks {
    static let name = Notification.Name("foo.n0rdy.nordyg.debug")
    static let selectRecord = Notification.Name("nordyg.debug.selectRecord")
    /// Read by CheckCard when it is created.
    nonisolated(unsafe) static var openCards: String? = nil

    static func install(model: AppModel) {
        DistributedNotificationCenter.default().addObserver(forName: name, object: nil, queue: .main) { note in
            guard let cmd = note.object as? String else { return }
            MainActor.assumeIsolated { handle(cmd, model) }
        }
    }

    private static var window: NSWindow? {
        NSApp.windows.first { $0.isVisible && $0.className.contains("AppKitWindow") } ?? NSApp.windows.first { $0.isVisible && $0.frame.width > 600 }
    }

    private static func handle(_ cmd: String, _ model: AppModel) {
        let parts = cmd.split(separator: " ", maxSplits: 1).map(String.init)
        let arg = parts.count > 1 ? parts[1] : ""
        switch parts.first {
        case "mode":
            if arg == "compare" { model.mode = .query; model.severalResolvers = true }
            else if let m = Mode(rawValue: arg) { model.mode = m; if m == .query { model.severalResolvers = false } }
        case "several": model.severalResolvers = arg != "off"
        case "example":
            if let i = Int(arg), model.mode.examples.indices.contains(i) { model.runExample(model.mode.examples[i]) }
        case "custom":
            // "custom add 192.0.2.53" / "custom remove 192.0.2.53": the real paths.
            let parts = arg.split(separator: " ").map(String.init)
            if parts.count == 2 {
                let ep = Endpoint(transport: "udp", address: parts[1] + ":53", tlsName: nil, url: nil, method: nil, label: nil)
                if parts[0] == "add" { model.addCustom(ep) } else { model.removeCustom(ep) }
            }
        case "preset":
            // "preset nextdns" opens its sheet; "preset nextdns abc123" sets the value.
            let parts = arg.split(separator: " ").map(String.init)
            if parts.count == 2 { model.configurePreset(parts[0], values: ["profile_id": parts[1]]) }
            else if parts.count == 1 { model.setupPreset = parts[0] }
            else { model.setupPreset = nil }
        case "unpreset": model.clearPreset(arg)
        case "macdns": model.showMacResolvers = arg != "off"
        case "dumpdns":
            // Writes the system resolver configuration as read in the sandbox.
            let lines = (DNSConfiguration.current() ?? []).map { r in
                "\(r.scoped ? "scoped" : "resolver") domain=\(r.domain ?? "-") ns=\(r.nameservers) port=\(r.port) if=\(r.interface ?? "-") order=\(r.order) flags=0x\(String(r.flags, radix: 16)) options=\(r.options ?? "-") search=\(r.searchDomains)"
            }
            let text = DNSConfiguration.current() == nil ? "UNAVAILABLE" : lines.joined(separator: "\n")
            try? text.write(to: FileManager.default.temporaryDirectory.appendingPathComponent("nordyg-dns.txt"), atomically: true, encoding: .utf8)
        case "checklist": model.showResolverChecklist = arg != "off"
        case "drill": model.compareDetail = Int(arg)
        case "name": model.name = arg
        case "run": model.run()
        case "clear": model.clearResult()
        case "history": model.historyFilter = Mode(rawValue: arg)
        case "select": NotificationCenter.default.post(name: selectRecord, object: Int(arg))
        case "type": model.type = arg.uppercased()
        case "resolver":
            let a = arg.lowercased()
            if let ep = model.allEndpoints.first(where: { $0.title.lowercased().contains(a) || $0.summary.lowercased().contains(a) }) {
                model.selected = ep
            }
        case "tab": model.resultTabs[model.mode] = arg
        case "compare":
            var set: Set<Endpoint> = []
            for term in arg.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces).lowercased() }) where !term.isEmpty {
                if term == "unreachable" {
                    let ep = Endpoint(transport: "udp", address: "192.0.2.1:53", tlsName: nil, url: nil, method: nil, label: "Unreachable test")
                    if !model.customEndpoints.contains(ep) { model.customEndpoints.append(ep) }
                    set.insert(ep)
                } else if let ep = model.allEndpoints.first(where: { $0.title.lowercased().contains(term) || $0.summary.lowercased().contains(term) }) {
                    set.insert(ep)
                }
            }
            model.compareSelection = set
        case "appearance":
            NSApp.appearance = arg == "light" ? NSAppearance(named: .aqua) : arg == "dark" ? NSAppearance(named: .darkAqua) : nil
        case "rerun": if let i = Int(arg), model.history.indices.contains(i) { model.rerun(model.history[i]) }
        case "cards": openCards = arg == "auto" ? nil : arg
        case "export":
            Task { @MainActor in
                let out = await model.exportCommand(arg) ?? "(nil)"
                try? out.write(to: FileManager.default.temporaryDirectory.appendingPathComponent("nordyg-export.txt"), atomically: true, encoding: .utf8)
            }
        case "size":
            let wh = arg.split(separator: " ").compactMap { Double($0) }
            if wh.count == 2, let w = window { w.setContentSize(NSSize(width: wh[0], height: wh[1])) }
        case "snapshot":
            if arg == "active" {
                NSApp.activate()
                window?.makeKeyAndOrderFront(nil)
            }
            Task { @MainActor in
                // Wait for a running op to finish so the result is in the shot.
                // "snapshot busy" captures mid-run, for progress UI.
                if arg == "busy" { try? await Task.sleep(for: .milliseconds(500)) }
                for _ in 0..<120 where model.isRunning && arg != "busy" { try? await Task.sleep(for: .milliseconds(250)) }
                try? await Task.sleep(for: .milliseconds(400))
                snapshot(drawn: arg == "drawn")
            }
        default: break
        }
    }

    private static func snapshot(drawn: Bool = false) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("nordyg-snapshot.png")
        if drawn, let view = window?.contentView, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
            view.cacheDisplay(in: view.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: url)
            return
        }
        // The window server composites glass and materials; capturing one's
        // own window needs no Screen Recording permission. The symbol is
        // looked up at run time because newer SDKs mark it unavailable.
        // A sheet is its own window; when one is open, that is what to see.
        let popover = NSApp.windows.first { $0.isVisible && $0.className.contains("Popover") }
        if let w = window?.attachedSheet ?? popover ?? window, let image = windowImage(w.windowNumber) {
            try? NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])?.write(to: url)
            return
        }
        // Fallback: AppKit's own drawing, which renders glass as blank.
        guard let view = window?.contentView?.superview ?? window?.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
    }

    private typealias CreateImage = @convention(c) (CGRect, UInt32, UInt32, UInt32) -> Unmanaged<CGImage>?

    private static func windowImage(_ number: Int) -> CGImage? {
        guard let handle = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_NOW),
              let sym = dlsym(handle, "CGWindowListCreateImage") else { return nil }
        let create = unsafeBitCast(sym, to: CreateImage.self)
        // kCGWindowListOptionIncludingWindow = 1 << 3; boundsIgnoreFraming = 1, bestResolution = 1 << 3
        return create(.null, 1 << 3, UInt32(number), 1 | (1 << 3))?.takeRetainedValue()
    }
}
#endif
