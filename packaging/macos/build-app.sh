#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
mode="${1:-local}"
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'This build requires macOS, full Xcode, XcodeGen, Rust and Apple SDKs.' >&2
  exit 1
fi
command -v xcodegen >/dev/null
xcodebuild -version
case "$mode" in
  local) scheme=FlowBridgeLocal ;;
  explicit-beta) scheme=FlowBridgeExplicitBeta ;;
  native)
    scheme=FlowBridge
    : "${DEVELOPMENT_TEAM:?Set DEVELOPMENT_TEAM to your real Apple signing team}"
    : "${FLOWBRIDGE_BUNDLE_ID:?Set FLOWBRIDGE_BUNDLE_ID to your registered app identifier}"
    ;;
  *) echo 'Usage: build-app.sh [local|explicit-beta|native]' >&2; exit 2 ;;
esac
bash "$root/native/macos/build-core.sh" universal
cd "$root/native/macos"
xcodegen generate --spec project.yml
out="${FLOWBRIDGE_BUILD_DIR:-$root/build/macos/$mode}"
args=(-project FlowBridge.xcodeproj -scheme "$scheme" -configuration Release -derivedDataPath "$out" \
  'ARCHS=arm64 x86_64' ONLY_ACTIVE_ARCH=NO)
if [[ "$mode" == local || "$mode" == explicit-beta ]]; then
  args+=(CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual CODE_SIGNING_ALLOWED=YES)
else
  args+=("DEVELOPMENT_TEAM=$DEVELOPMENT_TEAM" "FLOWBRIDGE_BUNDLE_ID=$FLOWBRIDGE_BUNDLE_ID")
  if [[ "${ALLOW_PROVISIONING_UPDATES:-0}" == 1 ]]; then args+=(-allowProvisioningUpdates); fi
  if [[ -n "${FLOWBRIDGE_APP_PROFILE:-}" || -n "${FLOWBRIDGE_EXTENSION_PROFILE:-}" ]]; then
    : "${FLOWBRIDGE_APP_PROFILE:?Provide both installed provisioning profile names}"
    : "${FLOWBRIDGE_EXTENSION_PROFILE:?Provide both installed provisioning profile names}"
    args+=(CODE_SIGN_STYLE=Manual "FLOWBRIDGE_APP_PROFILE=$FLOWBRIDGE_APP_PROFILE" "FLOWBRIDGE_EXTENSION_PROFILE=$FLOWBRIDGE_EXTENSION_PROFILE")
  fi
  if [[ -n "${CODE_SIGN_IDENTITY:-}" ]]; then args+=("CODE_SIGN_IDENTITY=$CODE_SIGN_IDENTITY"); fi
fi
xcodebuild "${args[@]}" build
product="FlowBridge"
if [[ "$mode" == explicit-beta ]]; then product="FlowBridgeExplicitBeta"; fi
app="$out/Build/Products/Release/$product.app"
test -d "$app"
xcrun lipo "$app/Contents/MacOS/$product" -verify_arch arm64 x86_64
if [[ "$mode" == explicit-beta ]]; then
  test ! -d "$app/Contents/Library/SystemExtensions"
  test ! -d "$app/Contents/PlugIns"
  identifier=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$app/Contents/Info.plist")
  [[ "$identifier" == org.flowbridge.FlowBridgeExplicitBeta ]] || { echo "Wrong beta bundle ID: $identifier" >&2; exit 1; }
  # A build without NE entitlement is necessary but not sufficient for
  # native activation; this beta never attempts activation.
  entitlements=$(codesign -d --entitlements :- "$app" 2>/dev/null || true)
  if [[ "$entitlements" == *com.apple.developer.networking.networkextension* ||
        "$entitlements" == *com.apple.developer.system-extension.install* ]]; then
    echo 'Explicit beta has forbidden Network Extension entitlements' >&2
    exit 1
  fi
fi
codesign --verify --deep --strict --verbose=2 "$app"
if [[ "$mode" == native ]]; then
  extension="$app/Contents/Library/SystemExtensions/$FLOWBRIDGE_BUNDLE_ID.extension.systemextension"
  test -d "$extension"
  codesign --verify --strict --verbose=2 "$extension"
  codesign -d --entitlements :- "$extension"
fi
printf 'Built app: %s\n' "$app"
