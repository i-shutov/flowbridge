#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
mode="${1:-local}"
case "$mode" in local|native) ;; *) echo 'Usage: build-pkg.sh [local|native]' >&2; exit 2 ;; esac
bash "$root/packaging/macos/build-app.sh" "$mode"
out="${FLOWBRIDGE_BUILD_DIR:-$root/build/macos/$mode}"
app="$out/Build/Products/Release/FlowBridge.app"
work="$(mktemp -d "${TMPDIR:-/tmp}/flowbridge-package.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/Applications" "$out/packages"
ditto "$app" "$work/root/Applications/FlowBridge.app"
pkgbuild --root "$work/root" --identifier "${FLOWBRIDGE_BUNDLE_ID:-org.flowbridge.FlowBridge}.installer" \
  --version 0.2.0 --install-location / "$work/FlowBridge-component.pkg"
# Product archive allows optional Developer ID Installer signing. No scripts,
# automatic startup, network settings changes, or extension activation on install.
args=(--package "$work/FlowBridge-component.pkg")
if [[ -n "${INSTALLER_SIGN_IDENTITY:-}" ]]; then args+=(--sign "$INSTALLER_SIGN_IDENTITY"); fi
result="$out/packages/FlowBridge-0.2.0-macOS-universal-$mode.pkg"
productbuild "${args[@]}" "$result"
pkgutil --check-signature "$result" || {
  if [[ -n "${INSTALLER_SIGN_IDENTITY:-}" ]]; then exit 1; fi
  echo 'Local package is unsigned; no Developer ID Installer identity was supplied.' >&2
}
printf 'Built installer: %s\n' "$result"
