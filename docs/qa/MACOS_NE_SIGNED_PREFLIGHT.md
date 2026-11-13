# macOS Network Extension — signed-bundle prerequisite gate

Scope: **FlowBridge 1.0 R02/R08 lab readiness**. This is not the explicit
SOCKS-only 0.3.0-beta.1 package (which intentionally has **no** NE), and
it is not macOS R02 native/traffic acceptance.

The current external dependency is a genuinely signed and entitled app +
system extension with Apple Team identity. Merely building a universal binary,
ad-hoc signing, or installing a package is not sufficient. Apple documents that
macOS system extension activation requires appropriate entitlements and code
signature. No SIP disabling, `systemextensionsctl developer on`, provisioning
bypass or trust-store changes are authorized by this checklist.

## Read-only command on an already built and installed signed FlowBridge.app

macOS 13+ with Python 3.10+, real Apple Developer Team and provisioned NE
capabilities; the operator supplies the Team ID locally (never commit keys,
certificates, identities or provisioning profiles). Run as the desktop user:

~~~bash
python3 tools/macos_ne_signed_preflight.py \
  --app /Applications/FlowBridge.app \
  --expected-bundle-id org.flowbridge.FlowBridge \
  --expected-team-id '<YOUR_10_CHARACTER_TEAM_ID>' \
  --output ./macos-ne-prerequisites.json
~~~

The script **only reads** Info.plist, checks installed paths and binaries,
and invokes `codesign --verify` / `codesign --display` on the app and
its single embedded system extension. It has no elevated operations, installer,
`systemextensionsctl`, profile changes, BCD/SIP, packet capture or network
settings commands. It checks:

1. The app is in /Applications or the current user's ~/Applications,
   not a symlink, and declares the expected app bundle ID.
2. Exactly one expected system extension is embedded at
   Contents/Library/SystemExtensions/org.flowbridge.FlowBridge.extension.systemextension;
   its bundle ID, executable and registered app-proxy + DNS-proxy provider
   classes match the compiled target.
3. Both signatures verify, code signing identifiers match the bundle IDs,
   and both Team IDs match the independently supplied Team ID.
4. App and extension have exactly the required
   app-proxy-provider-systemextension and dns-proxy-systemextension
   entitlements; the app also has
   com.apple.developer.system-extension.install=true.
   The extension itself must not claim that app-only entitlement.

Result codes:

| Verdict | Meaning |
| --- | --- |
| `BLOCKED` | Missing/mismatched physical prerequisite; stable error_code provided, nonzero process exit |
| `PREREQUISITES_PASS_NATIVE_NOT_RUN` | Signed *structure* matches. Start separate owner activation and native traffic acceptance; no release GO |

Both outcomes explicitly retain:
`activation_accepted=false`,
`native_packet_evidence_accepted=false`,
`dns_containment_proved=false`,
`publisher_release_approved=false`,
`release_accepted=false`.

The report omits local paths, hostnames, Team ID, certificate metadata,
entitlement payloads and user profiles. Review it with the actual developer
and native QA reviewer, not as a substitute for them.

## What this unblocks — and what it does not

The first gate can now distinguish a genuinely provisioned, valid installed NE
app from an ad-hoc or mismatched test package **without attempting activation**.
After a structural PASS the independent native R02 acceptance still requires:

- User-approved install/approve/activate of NETransparentProxyProvider and
  NEDNSProxyProvider on physical Apple Silicon and separate Intel Mac.
- Per-application selected/unselected IPv4/IPv6 TCP over actual SSH, original
  hostname/remote DNS evidence, local DNS and UDP/QUIC disclosures/containment.
- Crash, policy reauthorization, backpressure, Stop/restart, sleep/wake,
  upgrade, rollback, uninstall and system-extension cleanup evidence.
- Original signed app/pkg hashes, macOS build/arch, source SHA, testing commands,
  traffic traces and independent reviewer decision.
- Developer ID/notarization **publisher** checks for a later public candidate;
  developer-profile signatures do not silently count as release signing.

The network extension's existing source is still unaccepted; static signing
PASS never means that a TCP flow was intercepted or that an application cannot
use DIRECT.

## CI / negative control scope

~~~bash
python3 -m unittest discover -s tests \
  -p test_macos_ne_signed_preflight.py -v
~~~

The separate workflow only exercises **synthetic** bundles and mocked
codesign outputs on Linux and hosted macOS. It asserts that wrong Team ID,
missing signatures, wrong signing ID, missing/extra entitlements,
mismatched provider classes, multiple or linked extensions, non-macOS hosts
and malformed plists cannot be accepted. It does **not** have a signed app
or entitlement provisioning in CI and does not install any system extension.

Related: [Windows owner architecture Issue #41](https://github.com/i-shutov/flowbridge/issues/41),
[macOS native issue #2](https://github.com/i-shutov/flowbridge/issues/2),
[release contract](../RELEASE_1_0_PLAN.md).
