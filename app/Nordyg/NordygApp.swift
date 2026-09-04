import SwiftUI

@main
struct NordygApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("Nordyg") {
            ContentView()
                .environmentObject(model)
                .task { await model.load() }
                .frame(minWidth: 900, minHeight: 560)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Query") {
                Button("Run") { model.run() }.keyboardShortcut(.return, modifiers: .command).disabled(!model.canRun)
                Button("Cancel") { model.cancel() }.keyboardShortcut(".", modifiers: .command).disabled(!model.isRunning)
                Divider()
                Picker("Mode", selection: $model.mode) {
                    ForEach(Mode.allCases) { Text($0.title).tag($0) }
                }
            }
            CommandMenu("Export") {
                ExportMenu()
                    .environmentObject(model)
            }
        }
    }
}
