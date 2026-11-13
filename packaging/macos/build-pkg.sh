#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
mode="${1:-local}"
case "$mode" in local|native|explicit-beta) ;; *) echo 'Usage: build-pkg.sh [local|explicit-beta|native]' >&2; exit 2 ;; esac
bash "$root/packaging/macos/build-app.sh" "$mode"
out="${FLOWBRIDGE_BUILD_DIR:-$root/build/macos/$mode}"
product="FlowBridge"
pkg_identifier="${FLOWBRIDGE_BUNDLE_ID:-org.flowbridge.FlowBridge}.installer"
pkg_version=0.2.0
if [[ "$mode" == explicit-beta ]]; then
  product="FlowBridgeExplicitBeta"
  pkg_identifier="org.flowbridge.FlowBridgeExplicitBeta.installer"
  pkg_version=$(python3 "$root/tools/explicit_beta_metadata.py" field macos_short_version)
  if [[ -n "${INSTALLER_SIGN_IDENTITY:-}" ]]; then
    echo 'This engineering beta contract requires an unsigned pkg; release signing is a separate gate.' >&2
    exit 1
  fi
fi
app="$out/Build/Products/Release/$product.app"
work="$(mktemp -d "${TMPDIR:-/tmp}/flowbridge-package.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/Applications" "$out/packages"
ditto "$app" "$work/root/Applications/$product.app"
pkgbuild --analyze --root "$work/root" "$work/components.plist"
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$work/components.plist"
pkgbuild --root "$work/root" --component-plist "$work/components.plist" --identifier "$pkg_identifier" \
  --version "$pkg_version" --install-location / "$work/FlowBridge-component.pkg"
# No scripts, automatic startup, network changes or extension activation on install.
args=(--package "$work/FlowBridge-component.pkg")
if [[ -n "${INSTALLER_SIGN_IDENTITY:-}" ]]; then args+=(--sign "$INSTALLER_SIGN_IDENTITY"); fi
result="$out/packages/FlowBridge-0.2.0-macOS-universal-$mode.pkg"
if [[ "$mode" == explicit-beta ]]; then
  result="$out/packages/$(python3 "$root/tools/explicit_beta_metadata.py" field macos_installer)"
fi
productbuild "${args[@]}" "$result"
pkgutil --check-signature "$result" || {
  if [[ -n "${INSTALLER_SIGN_IDENTITY:-}" ]]; then exit 1; fi
  echo 'Local package is unsigned; no Developer ID Installer identity was supplied.' >&2
}
if [[ "$mode" == explicit-beta ]]; then
  # Inspect the ACTUAL package contents, not merely the source-tree scheme.
  listing=$(pkgutil --payload-files "$result")
  [[ "$listing" == *"FlowBridgeExplicitBeta.app/"* ]] || { echo 'Beta app missing from package' >&2; exit 1; }
  if [[ "$listing" == *"FlowBridge.app/"* ||
        "$listing" == *".systemextension"* ||
        "$listing" == *"SystemExtensions"* ||
        "$listing" == *"Library/LaunchDaemons"* ||
        "$listing" == *"Library/PrivilegedHelperTools"* ]]; then
    echo 'Explicit beta package includes forbidden native/system payload' >&2
    exit 1
  fi
  python3 "$root/tools/explicit_beta_metadata.py" macos-manifest --pkg "$result" \
    --output "$root/build/verification/explicit-macos-package.json"
  shasum -a 256 "$result" > "$result.sha256"
fi
printf 'Built installer: %s\n' "$result"
