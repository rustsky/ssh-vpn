#!/usr/bin/env bash
# Sign SshVpn.app and wrap it in a DMG. Usage: scripts/macos-dmg.sh <SshVpn.app> <out.dmg>
#
# dx leaves the app with only the linker's ad-hoc signature on the binary, which does not
# seal the bundle; once downloaded, Gatekeeper then calls the app "damaged". So the bundle
# is always signed here:
#   - with MACOS_SIGN_IDENTITY set (a Developer ID Application identity in the keychain): a
#     real signature with the hardened runtime, notarized and stapled if APPLE_ID,
#     APPLE_TEAM_ID and APPLE_APP_PASSWORD are set too. Opens without any warning.
#   - otherwise ad-hoc. macOS then says it cannot verify the developer, and the app is opened
#     once via System Settings > Privacy & Security > Open Anyway.
set -euo pipefail

APP=$1
DMG=$2
IDENTITY=${MACOS_SIGN_IDENTITY:--}

if [[ $IDENTITY == - ]]; then
  codesign --force --deep --sign - "$APP"
else
  codesign --force --deep --options runtime --timestamp --sign "$IDENTITY" "$APP"
fi
codesign --verify --deep --strict --verbose=2 "$APP"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "SSH VPN" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null

if [[ $IDENTITY != - ]]; then
  codesign --force --timestamp --sign "$IDENTITY" "$DMG"
  if [[ -n ${APPLE_ID:-} && -n ${APPLE_TEAM_ID:-} && -n ${APPLE_APP_PASSWORD:-} ]]; then
    xcrun notarytool submit "$DMG" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
      --password "$APPLE_APP_PASSWORD" --wait
    xcrun stapler staple "$DMG"
  fi
fi
echo "$DMG"
