#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'macOS with Xcode command-line tools is required to build the Darwin static library.' >&2
  exit 1
fi
export MACOSX_DEPLOYMENT_TARGET=13.0
architectures="${1:-universal}"
case "$architectures" in
  universal) architectures='arm64 x86_64' ;;
  arm64|x86_64) ;;
  *) echo 'Usage: build-core.sh [universal|arm64|x86_64]' >&2; exit 2 ;;
esac
for architecture in $architectures; do
  case "$architecture" in
    arm64) target=aarch64-apple-darwin ;;
    x86_64) target=x86_64-apple-darwin ;;
  esac
  rustup target add "$target"
  cargo build --locked --release -p flowbridge-ffi --target "$target"
  mkdir -p "native/macos/lib/$architecture"
  cp "${CARGO_TARGET_DIR:-target}/$target/release/libflowbridge_ffi.a" "native/macos/lib/$architecture/"
done
if [[ "$architectures" == 'arm64 x86_64' ]]; then
  mkdir -p native/macos/lib/universal
  xcrun lipo -create native/macos/lib/arm64/libflowbridge_ffi.a native/macos/lib/x86_64/libflowbridge_ffi.a \
    -output native/macos/lib/universal/libflowbridge_ffi.a
  xcrun lipo native/macos/lib/universal/libflowbridge_ffi.a -verify_arch arm64 x86_64
fi
