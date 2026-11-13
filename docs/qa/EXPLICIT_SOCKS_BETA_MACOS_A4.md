# A4: isolated macOS explicit SOCKS beta — engineering candidate

**Status:** source/package changes prepared; hosted build and real Mac installation NOT YET ACCEPTED.
Scope ONLY PR #59. Windows WFP/NDISRD, macOS NE and system DNS outside this beta.

## New identities, no system extension

- XcodeGen FlowBridgeExplicitBeta target and scheme, ad-hoc signing, separate bundle
  org.flowbridge.FlowBridgeExplicitBeta, separate Info.plist, no NE entitlement or extension dependency.
- Existing FlowBridgeLocal and FlowBridge native build schemes retained.
- New profile root: ~/Library/Application Support/FlowBridgeExplicitBeta/
  with desktop.json and profile.json. Stable FlowBridge app and profile untouched.
- Forged or old native mode cannot activate: load resets mode to 0; save, start,
  configuredProfile and apply have compile-time guarded refusal; GUI hides mode picker.
- Output: FlowBridgeExplicitBeta.app and
  FlowBridge-0.2.0-explicit-candidate-macOS-universal.pkg, distinct installer receipt.
- Package builder inspects actual pkgutil payload; forbids system extensions,
  LaunchDaemons, privileged helper, stable FlowBridge.app and security entitlements.

## Exact-source hosted and native acceptance

Run on macOS with Xcode, XcodeGen, Rust arm64 and x86_64 targets:

    python3 -m pip install PyYAML==6.0.2
    python3 tests/macos_explicit_beta_scope.py
    bash packaging/macos/build-pkg.sh explicit-beta
    python3 tests/macos_explicit_beta_scope.py \
      --app build/macos/explicit-beta/Build/Products/Release/FlowBridgeExplicitBeta.app \
      --pkg build/macos/explicit-beta/packages/FlowBridge-0.2.0-explicit-candidate-macOS-universal.pkg

CI explicit-socks-beta-macos.yml verifies source scope and actual app/pkg contents;
records exact SHA and original bytes. It does NOT install the app or activate NE.

Full A4 GO additionally needs independent native ARM64+Intel Mac checks:
install, launch GUI, configured SOCKS5h, real owned OpenSSH auth and host-key reject,
Stop/Quit, update/uninstall and stable-profile preservation. Capture original logs
and package hashes. CI green = HOSTED_BUILD_ONLY, not native A4 PASS.

Signed public package, notarization and real signing credentials require separate
approval; the current output is unsigned engineering candidate only.
No driver/filter/system proxy/firewall/DNS action, no native PacketBound proof,
no claim of DIRECT blocking for apps outside explicit client SOCKS configuration.

**v0.3.0-beta.1 NO-GO; v1.0.0 NO-GO until their respective gates pass.**

## Next evidence handoff

Record the frozen workflow run/job conclusions, original package SHA256,
Xcode version, architectures, the native app/pkg audit JSON and explicit
separate-profile evidence. A hosted build alone never authorizes a public tag.
