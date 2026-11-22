#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p artifacts/RAVEN-Disassembler/RAVEN\ Disassembler.app/Contents/MacOS
cp target/release/raven-gui 'artifacts/RAVEN-Disassembler/RAVEN Disassembler.app/Contents/MacOS/raven-gui'
cp target/release/raven target/release/raven-mcp artifacts/RAVEN-Disassembler/
cat > 'artifacts/RAVEN-Disassembler/RAVEN Disassembler.app/Contents/Info.plist' <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.raven.disassembler</string>
<key>CFBundleName</key><string>RAVEN Disassembler</string>
<key>CFBundleExecutable</key><string>raven-gui</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>NSHighResolutionCapable</key><true/>
<key>LSMinimumSystemVersion</key><string>10.15</string>
</dict></plist>
PLIST
# Ad-hoc developer signature; this is not Apple notarization.
codesign --force --sign - 'artifacts/RAVEN-Disassembler/RAVEN Disassembler.app'
codesign --verify --deep --strict 'artifacts/RAVEN-Disassembler/RAVEN Disassembler.app'
cp README.md LICENSE artifacts/RAVEN-Disassembler/
cp -R docs artifacts/RAVEN-Disassembler/
cp examples/mcp.json artifacts/RAVEN-Disassembler/mcp.json
/usr/bin/ditto -c -k --sequesterRsrc --keepParent artifacts/RAVEN-Disassembler artifacts/RAVEN-Disassembler-macos.zip
shasum -a 256 artifacts/RAVEN-Disassembler-macos.zip > artifacts/RAVEN-Disassembler-macos.zip.sha256
