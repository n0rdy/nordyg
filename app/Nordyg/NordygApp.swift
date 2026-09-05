import SwiftUI

@main
struct NordygApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("Nordyg") {
            ContentView()
                .environmentObject(model)
                .environmentObject(model.watches)
                .task { await model.load() }
                .frame(minWidth: 900, minHeight: 560)
        }
        MenuBarExtra {
            WatchMenu()
                .environmentObject(model.watches)
        } label: {
            Image(systemName: model.watches.watches.isEmpty ? "eye" : (model.watches.anyUnread ? "eye.trianglebadge.exclamationmark" : "eye.fill"))
        }
        .menuBarExtraStyle(.window)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Query") {
                Button("Run") { model.run() }.keyboardShortcut(.return, modifiers: .command).disabled(!model.canRun)
                Button("Cancel") { model.cancel() }.keyboardShortcut(".", modifiers: .command).disabled(!model.isRunning)
                Divider()
                Picker("Mode", selection: $model.mode) {
                    ForEach(Mode.allCases) { Text($0.title).tag($0) }
                }
                Divider()
                Menu("Watch this query") {
                    ForEach(WatchCenter.intervals, id: \.self) { s in
                        Button("Every \(WatchCenter.intervalLabel(s))") { model.watchCurrent(interval: s) }
                    }
                }.disabled(!model.canWatch)
            }
            CommandMenu("Export") {
                ExportMenu()
                    .environmentObject(model)
            }
        }
    }
}
