// Renders the layer image of the Icon Composer package (app/Nordyg/AppIcon.icon)
// from the logo tile: the square tile scaled to a full 1024 canvas. macOS 26
// masks it into its squircle; Xcode generates the legacy sizes for macOS 14/15.
// Usage: swift app/tools/make-icon.swift <tile.png> <AppIcon.icon dir>
import AppKit

let args = CommandLine.arguments
guard args.count == 3, let src = NSImage(contentsOfFile: args[1]), let tile = src.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    FileHandle.standardError.write("usage: make-icon.swift <tile.png> <AppIcon.icon>\n".data(using: .utf8)!)
    exit(1)
}
let ctx = CGContext(data: nil, width: 1024, height: 1024, bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.interpolationQuality = .high
ctx.draw(tile, in: CGRect(x: 0, y: 0, width: 1024, height: 1024))
let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
let out = args[2] + "/Assets/logo.png"
try! FileManager.default.createDirectory(atPath: args[2] + "/Assets", withIntermediateDirectories: true)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
