import AppKit
import SwiftUI
import WiSecuredCore

/// Colours and the logo-A shield, drawn in code (same shapes as the mockup).
enum Theme {
    static let accent = Color(red: 0.235, green: 0.784, blue: 0.706)          // #3CC8B4
    static let accentNS = NSColor(srgbRed: 0.235, green: 0.784, blue: 0.706, alpha: 1)
    static let card = Color(nsColor: NSColor(name: nil) { $0.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        ? NSColor(srgbRed: 0.086, green: 0.106, blue: 0.122, alpha: 1) : NSColor(srgbRed: 0.953, green: 0.961, blue: 0.969, alpha: 1) })
    static let row = Color.primary.opacity(0.05)

    static let green = NSColor(srgbRed: 0.204, green: 0.780, blue: 0.349, alpha: 1)    // #34C759
    static let yellow = NSColor(srgbRed: 1.0, green: 0.839, blue: 0.039, alpha: 1)     // #FFD60A
    static let red = NSColor(srgbRed: 1.0, green: 0.353, blue: 0.306, alpha: 1)        // #FF5A4E
    static let grey = NSColor.secondaryLabelColor

    static func color(_ verdict: Verdict) -> NSColor {
        switch verdict {
        case .safe: return green
        case .careful: return yellow
        case .danger: return red
        case .checking, .offline: return grey
        }
    }

    static func color(_ status: CheckStatus) -> Color {
        switch status {
        case .ok: return Color(nsColor: green)
        case .info: return Color(nsColor: .systemBlue)
        case .warn: return Color(nsColor: yellow)
        case .danger: return Color(nsColor: red)
        case .unknown: return .secondary
        }
    }
}

/// Logo A: a shield with a Wi-Fi signal inside, in a 64×64 design grid (y down, like the SVG).
enum Shield {
    static func outline() -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 32, y: 6))
        p.line(to: NSPoint(x: 50, y: 12.5))
        p.line(to: NSPoint(x: 50, y: 29))
        p.curve(to: NSPoint(x: 32, y: 56), controlPoint1: NSPoint(x: 50, y: 42), controlPoint2: NSPoint(x: 42, y: 51.5))
        p.curve(to: NSPoint(x: 14, y: 29), controlPoint1: NSPoint(x: 22, y: 51.5), controlPoint2: NSPoint(x: 14, y: 42))
        p.line(to: NSPoint(x: 14, y: 12.5))
        p.close()
        return p
    }

    /// One signal arc between two points, bulging upwards (quadratic approximation of a circle arc).
    static func arc(from a: NSPoint, to b: NSPoint, control: NSPoint) -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: a)
        let c1 = NSPoint(x: a.x + 2.0 / 3.0 * (control.x - a.x), y: a.y + 2.0 / 3.0 * (control.y - a.y))
        let c2 = NSPoint(x: b.x + 2.0 / 3.0 * (control.x - b.x), y: b.y + 2.0 / 3.0 * (control.y - b.y))
        p.curve(to: b, controlPoint1: c1, controlPoint2: c2)
        p.lineCapStyle = .round
        return p
    }

    /// Logo A's Wi-Fi signal: two arcs and a dot (same geometry as the app icon and the mockup).
    static func drawSignal(color: NSColor, width: CGFloat) {
        color.setStroke()
        for signal in [arc(from: NSPoint(x: 21, y: 30), to: NSPoint(x: 43, y: 30), control: NSPoint(x: 32, y: 20.8)),
                       arc(from: NSPoint(x: 25.5, y: 35.5), to: NSPoint(x: 38.5, y: 35.5), control: NSPoint(x: 32, y: 29.9))] {
            signal.lineWidth = width
            signal.stroke()
        }
        color.setFill()
        NSBezierPath(ovalIn: NSRect(x: 29.3, y: 39.3, width: 5.4, height: 5.4)).fill()
    }

    /// Menu bar / dropdown image for a verdict: filled coloured shield with a dark mark
    /// (signal for safe/careful, "!" for danger), or a grey outline while checking / offline.
    /// `tight` crops to the shield itself (x 12–52, y 4–56 of the grid) so it fills the menu bar
    /// height like other icons; otherwise the full 64-unit square with its margins.
    static func image(for verdict: Verdict, size: CGFloat, tight: Bool = false) -> NSImage {
        let box = tight ? NSRect(x: 12, y: 4, width: 40, height: 52) : NSRect(x: 0, y: 0, width: 64, height: 64)
        let scale = size / box.height
        let image = NSImage(size: NSSize(width: box.width * scale, height: size), flipped: true) { _ in
            NSGraphicsContext.current?.cgContext.concatenate(
                CGAffineTransform(a: scale, b: 0, c: 0, d: scale, tx: -box.minX * scale, ty: -box.minY * scale))
            let ink = NSColor(srgbRed: 0.06, green: 0.07, blue: 0.08, alpha: 1)
            switch verdict {
            case .checking, .offline:
                let outline = outline()
                outline.lineWidth = 4.4
                outline.lineJoinStyle = .round
                NSColor.secondaryLabelColor.setStroke()
                outline.stroke()
                drawSignal(color: .secondaryLabelColor, width: 4)
            case .danger:
                Theme.red.setFill()
                outline().fill()
                ink.setStroke()
                let bar = NSBezierPath()
                bar.move(to: NSPoint(x: 32, y: 20))
                bar.line(to: NSPoint(x: 32, y: 36))
                bar.lineWidth = 6
                bar.lineCapStyle = .round
                bar.stroke()
                ink.setFill()
                NSBezierPath(ovalIn: NSRect(x: 28.4, y: 41.4, width: 7.2, height: 7.2)).fill()
            case .safe, .careful:
                Theme.color(verdict).setFill()
                outline().fill()
                drawSignal(color: ink, width: 4)
            }
            return true
        }
        image.accessibilityDescription = "WiSecured: \(verdict.title)"
        return image
    }
}
