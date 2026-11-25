import SwiftUI

@main
struct NordygApp: App {
    @StateObject private var model = AppModel()
    @StateObject private var updater = Updater()

    var body: some Scene {
        WindowGroup("Nordyg") {
            ContentView()
                .environmentObject(model)
                .environmentObject(model.watches)
                .task {
                    await model.load()
                    #if DEBUG
                    DebugHooks.install(model: model)
                    #endif
                }
                // Below 1000 points the toolbar runs out of room and Clear and
                // Copy collapse into its overflow menu.
                .frame(minWidth: 1000, minHeight: 600)
        }
        // First launch only: after that macOS restores the last size.
        .defaultSize(width: 1240, height: 800)
        MenuBarExtra(isInserted: Binding(get: { !model.watches.watches.isEmpty }, set: { _ in })) {
            WatchMenu()
                .environmentObject(model.watches)
        } label: {
            Image(
                systemName: model.watches.watches.isEmpty
                    ? "eye" : (model.watches.anyUnread ? "eye.trianglebadge.exclamationmark" : "eye.fill"))
        }
        .menuBarExtraStyle(.window)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Nordyg") { AboutPanel.show() }
                if updater.isAvailable {
                    Button("Check for Updates…") { updater.check() }.disabled(!updater.canCheck)
                }
            }
            CommandGroup(replacing: .help) {
                Button("Ask a question or report a bug") { NSWorkspace.shared.open(Links.discussions) }
                Divider()
                Button("Source code") { NSWorkspace.shared.open(Links.source) }
            }
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Query") {
                Button("Run") { model.run() }.keyboardShortcut(.return, modifiers: .command).disabled(!model.canRun)
                Button("Cancel") { model.cancel() }.keyboardShortcut(".", modifiers: .command).disabled(!model.isRunning)
                Button("Clear Result") { model.clearResult() }.keyboardShortcut("k", modifiers: .command).disabled(!model.canClear)
                Divider()
                Picker("Mode", selection: $model.mode) {
                    ForEach(Mode.allCases) { Text($0.title).tag($0) }
                }
                Divider()
                Menu("Watch this query") {
                    WatchIntervalButtons(model: model)
                }.disabled(!model.canWatch)
            }
            CommandMenu("Export") {
                ExportMenu()
                    .environmentObject(model)
            }
        }
    }
}
