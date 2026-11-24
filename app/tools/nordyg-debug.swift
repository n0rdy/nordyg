import Foundation

// Sends one command to a running Debug build of Nordyg (see app/Nordyg/DebugHooks.swift).
// Build once: make debug-tool
// Use:        app/build/nordyg-debug mode health; app/build/nordyg-debug name example.com
//             app/build/nordyg-debug run; app/build/nordyg-debug snapshot
// The snapshot lands in ~/Library/Containers/foo.n0rdy.nordyg/Data/tmp/nordyg-snapshot.png.
let cmd = CommandLine.arguments.dropFirst().joined(separator: " ")
DistributedNotificationCenter.default().postNotificationName(
    .init("foo.n0rdy.nordyg.debug"), object: cmd, userInfo: nil, deliverImmediately: true)
