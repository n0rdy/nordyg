// Renders the app icon: a violet gradient tile with a chain of three nodes,
// the last one locked. Usage: swift app/tools/make-icon.swift <outdir>
import AppKit

let outDir = CommandLine.arguments.dropFirst().first ?? "."
let sizes: [(Int, Int)] = [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)]

func draw(px: Int) -> NSImage {
    let s = CGFloat(px)
    let img = NSImage(size: NSSize(width: s, height: s))
    img.lockFocus()
    guard let ctx = NSGraphicsContext.current?.cgContext else { return img }
    // Apple's icon grid: the tile is ~80% of the canvas.
    let inset = s * 0.10
    let tile = CGRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let path = CGPath(roundedRect: tile, cornerWidth: tile.width * 0.225, cornerHeight: tile.width * 0.225, transform: nil)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.01), blur: s * 0.03, color: NSColor.black.withAlphaComponent(0.35).cgColor)
    ctx.addPath(path); ctx.clip()
    let colors = [NSColor(srgbRed: 0.53, green: 0.42, blue: 0.93, alpha: 1).cgColor, NSColor(srgbRed: 0.24, green: 0.16, blue: 0.55, alpha: 1).cgColor] as CFArray
    let grad = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0, 1])!
    ctx.drawLinearGradient(grad, start: CGPoint(x: tile.minX, y: tile.maxY), end: CGPoint(x: tile.maxX, y: tile.minY), options: [])
    ctx.restoreGState()

    // Chain of three nodes from top-left to bottom-right.
    let pts = [CGPoint(x: 0.30, y: 0.70), CGPoint(x: 0.50, y: 0.50), CGPoint(x: 0.70, y: 0.30)].map { CGPoint(x: tile.minX + $0.x * tile.width, y: tile.minY + $0.y * tile.height) }
    let r = tile.width * 0.085
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.85).cgColor)
    ctx.setLineWidth(tile.width * 0.045)
    ctx.setLineCap(.round)
    ctx.move(to: pts[0]); ctx.addLine(to: pts[1]); ctx.addLine(to: pts[2]); ctx.strokePath()
    for (i, p) in pts.enumerated() {
        ctx.setFillColor(NSColor.white.cgColor)
        ctx.fillEllipse(in: CGRect(x: p.x - r, y: p.y - r, width: 2 * r, height: 2 * r))
        if i == 2 {
            // Lock body on the last node.
            ctx.setFillColor(NSColor(srgbRed: 0.24, green: 0.16, blue: 0.55, alpha: 1).cgColor)
            let w = r * 0.9, h = r * 0.7
            ctx.fill(CGRect(x: p.x - w / 2, y: p.y - h * 0.75, width: w, height: h))
            ctx.setStrokeColor(NSColor(srgbRed: 0.24, green: 0.16, blue: 0.55, alpha: 1).cgColor)
            ctx.setLineWidth(r * 0.22)
            ctx.addArc(center: CGPoint(x: p.x, y: p.y + h * 0.1), radius: w * 0.32, startAngle: 0, endAngle: .pi, clockwise: false)
            ctx.strokePath()
        }
    }
    img.unlockFocus()
    return img
}

var entries: [String] = []
for (pt, scale) in sizes {
    let px = pt * scale
    let img = draw(px: px)
    let rep = NSBitmapImageRep(cgImage: img.cgImage(forProposedRect: nil, context: nil, hints: nil)!)
    rep.size = NSSize(width: px, height: px)
    let name = "icon_\(pt)x\(pt)\(scale == 2 ? "@2x" : "").png"
    try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: "\(outDir)/\(name)"))
    entries.append("{ \"filename\" : \"\(name)\", \"idiom\" : \"mac\", \"scale\" : \"\(scale)x\", \"size\" : \"\(pt)x\(pt)\" }")
}
let json = "{\n  \"images\" : [\n    " + entries.joined(separator: ",\n    ") + "\n  ],\n  \"info\" : { \"author\" : \"xcode\", \"version\" : 1 }\n}\n"
try! json.write(toFile: "\(outDir)/Contents.json", atomically: true, encoding: .utf8)
print("wrote \(entries.count) icon sizes to \(outDir)")
