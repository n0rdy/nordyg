import Combine
import Sparkle

/// In-app updates through Sparkle, for the signed releases. The feed and the
/// public key are in Info.plist (set in project.yml). Debug builds, and any
/// build without a public key, never start the updater, so test runs are not
/// offered the published release.
@MainActor
final class Updater: ObservableObject {
    @Published private(set) var canCheck = false
    private let controller: SPUStandardUpdaterController?

    init() {
        let key = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String ?? ""
        #if DEBUG
        let enabled = false
        #else
        let enabled = !key.isEmpty
        #endif
        guard enabled else {
            controller = nil
            return
        }
        let c = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        controller = c
        c.updater.publisher(for: \.canCheckForUpdates).receive(on: DispatchQueue.main).assign(to: &$canCheck)
    }

    /// False when the updater is off, so the menu item can be left out.
    var isAvailable: Bool { controller != nil }

    func check() { controller?.checkForUpdates(nil) }
}
