// make-icon.swift — draws the WiSecured app icon (logo A: teal shield + Wi-Fi signal on slate)
// and writes a macOS .iconset folder.
//
// HOW TO RUN (from the project folder; build.sh does this for you):
//   swift tools/make-icon.swift .build/icon/AppIcon.iconset
//   iconutil -c icns .build/icon/AppIcon.iconset -o Resources/AppIcon.icns

import AppKit

let outDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
try FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

let teal = NSColor(srgbRed: 0.235, green: 0.784, blue: 0.706, alpha: 1)
let slate = NSColor(srgbRed: 0.086, green: 0.106, blue: 0.122, alpha: 1)
let edge = NSColor(srgbRed: 0.18, green: 0.212, blue: 0.247, alpha: 1)

/// Draws the 1024-pt master into the current context (y up).
func drawIcon(_ size: CGFloat) {
    let s = size / 1024
    // macOS icon grid: 824×824 rounded square centred in 1024.
    let body = NSRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    let square = NSBezierPath(roundedRect: body, xRadius: 185 * s, yRadius: 185 * s)
    slate.setFill(); square.fill()
    edge.setStroke(); square.lineWidth = 6 * s; square.stroke()

    // Logo A in its 64-unit grid (SVG y-down), mapped into the square with margin.
    let unit = 560 * s / 64, ox = 512 * s - 32 * unit, oy = 512 * s + 31 * unit
    func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: ox + x * unit, y: oy - y * unit) }

    let shield = NSBezierPath()
    shield.move(to: p(32, 6)); shield.line(to: p(50, 12.5)); shield.line(to: p(50, 29))
    shield.curve(to: p(32, 56), controlPoint1: p(50, 42), controlPoint2: p(42, 51.5))
    shield.curve(to: p(14, 29), controlPoint1: p(22, 51.5), controlPoint2: p(14, 42))
    shield.line(to: p(14, 12.5)); shield.close()
    shield.lineWidth = 3.4 * unit
    shield.lineJoinStyle = .round
    teal.setStroke(); shield.stroke()

    func arc(_ a: NSPoint, _ b: NSPoint, _ c: NSPoint) {
        let path = NSBezierPath()
        path.move(to: a)
        path.curve(to: b, controlPoint1: NSPoint(x: a.x + 2 / 3 * (c.x - a.x), y: a.y + 2 / 3 * (c.y - a.y)),
                   controlPoint2: NSPoint(x: b.x + 2 / 3 * (c.x - b.x), y: b.y + 2 / 3 * (c.y - b.y)))
        path.lineWidth = 3.4 * unit
        path.lineCapStyle = .round
        path.stroke()
    }
    arc(p(21, 30), p(43, 30), p(32, 20.8))
    arc(p(25.5, 35), p(38.5, 35), p(32, 29.45))
    teal.setFill()
    NSBezierPath(ovalIn: NSRect(x: p(32, 41).x - 2.4 * unit, y: p(32, 41).y - 2.4 * unit, width: 4.8 * unit, height: 4.8 * unit)).fill()
}

let sizes: [(name: String, px: Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256), ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]
for (name, px) in sizes {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: px, height: px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    drawIcon(CGFloat(px))
    NSGraphicsContext.restoreGraphicsState()
    try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: "\(outDir)/\(name).png"))
}
print("Wrote \(sizes.count) PNGs to \(outDir)")
