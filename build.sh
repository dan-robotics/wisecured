#!/bin/zsh
# build.sh — builds WiSecured as an .app and a drag-to-install DMG.
#
# HOW TO RUN (from the project folder):
#   ./build.sh            → dist/<version>-<timestamp>/WiSecured.app + dist/WiSecured-<version>-<timestamp>.dmg
#   ./build.sh --help
#
# Uses only built-in tools: swift, iconutil, codesign (ad-hoc, not notarized), hdiutil.
# Never deletes anything: every build gets its own fresh folder and a uniquely named DMG.
# First open on another Mac: System Settings › Privacy & Security › Open Anyway.

set -euo pipefail

VERSION="0.2.1"
BUNDLE_ID="io.github.dan-robotics.WiSecured"
NAME="WiSecured"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

cd "$(dirname "$0")"
STAMP="$(date +%Y%m%d-%H%M%S)"
DIR="dist/${VERSION}-${STAMP}"
APP="${DIR}/${NAME}.app"
DMG="dist/${NAME}-${VERSION}-${STAMP}.dmg"
STAGING=".build/dmg-staging/${STAMP}"
mkdir -p "${DIR}" Resources

# App icon, redrawn only when the drawing code changes.
if [[ ! -f Resources/AppIcon.icns || tools/make-icon.swift -nt Resources/AppIcon.icns ]]; then
  echo "▶ drawing app icon"
  swift tools/make-icon.swift .build/icon/AppIcon.iconset
  iconutil -c icns .build/icon/AppIcon.iconset -o Resources/AppIcon.icns
fi

echo "▶ 1/4  swift build (release)"
swift build -c release --product WiSecured
BIN="$(swift build -c release --product WiSecured --show-bin-path)/WiSecured"

echo "▶ 2/4  assemble ${APP}"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources"
cp -f Resources/AppIcon.icns "${APP}/Contents/Resources/AppIcon.icns"
cp -f "${BIN}" "${APP}/Contents/MacOS/${NAME}"
cat > "${APP}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>${NAME}</string>
  <key>CFBundleDisplayName</key><string>${NAME}</string>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleExecutable</key><string>${NAME}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${STAMP}</string>
  <key>LSMinimumSystemVersion</key><string>15.0</string>
  <key>LSUIElement</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSLocationUsageDescription</key><string>macOS only shows Wi-Fi network names and security types to apps with Location permission. WiSecured never uses or stores your location.</string>
  <key>NSLocationWhenInUseUsageDescription</key><string>macOS only shows Wi-Fi network names and security types to apps with Location permission. WiSecured never uses or stores your location.</string>
  <key>NSLocalNetworkUsageDescription</key><string>WiSecured asks your network's own DNS server and reads your router's address to check that nothing is tampering with your connection. It never scans or contacts other devices.</string>
  <key>NSHumanReadableCopyright</key><string>Daniel Andries</string>
</dict>
</plist>
PLIST

echo "▶ 3/4  ad-hoc codesign"
codesign --force --sign - --timestamp=none "${APP}"
codesign --verify --verbose=1 "${APP}"

echo "▶ 4/4  DMG → ${DMG}"
mkdir -p "${STAGING}"
ditto "${APP}" "${STAGING}/${NAME}.app"
ln -sf /Applications "${STAGING}/Applications"
hdiutil create -volname "${NAME}" -srcfolder "${STAGING}" -format UDZO -fs HFS+ "${DMG}" >/dev/null

echo ""
echo "✔ Built:"
echo "   App: ${APP}"
echo "   DMG: ${DMG}"
