# FlowBridge 0.2.0 for macOS

This directory contains real build/package entry points for the SwiftUI app and
Network Extension adapter. **The source was prepared on Linux. No Xcode compile,
macOS runtime test, `.app`, signed extension or `.pkg` has been produced or
validated in that environment.** Run the following on a Mac before distributing.

## Local SOCKS application

Prerequisites: macOS 13+, full Xcode selected with its license accepted, XcodeGen
2.38+, and Rust/rustup. Use an Xcode release that supports your macOS version.

From the repository root:

```sh
./packaging/macos/build-app.sh local
./packaging/macos/build-pkg.sh local
```

`build-core.sh universal` builds the Rust static library separately for
`aarch64-apple-darwin` and `x86_64-apple-darwin`, then merges with `lipo`. XcodeGen
creates the Xcode project and Xcode links the real engine into the app. The local
scheme uses ad hoc signing and has **no extension target dependency or restricted
entitlements**. It remains useful without an Apple developer account. This is a
local development artifact, not a notarized distribution build.

Outputs, unless `FLOWBRIDGE_BUILD_DIR` overrides the build directory:

- `build/macos/local/Build/Products/Release/FlowBridge.app`
- `build/macos/local/packages/FlowBridge-0.2.0-macOS-universal-local.pkg`

The product installer places the app in `/Applications`. It does not launch it,
activate capture, change system proxy settings or add login/background items.
The `.pkg` is unsigned unless `INSTALLER_SIGN_IDENTITY` is set to your installed
Developer ID Installer certificate name. The script uses `pkgbuild` followed by
`productbuild`; it does not rename another archive to `.pkg`.

Default routing profile: local SOCKS5 at `127.0.0.1:1081`, upstream SOCKS5 at
`127.0.0.1:1080`. The desktop now offers an integrated SSH watchdog and an Existing
Proxy mode. Integrated mode requires the user to supply their SSH host and user;
it starts its own OpenSSH dynamic forward. Existing Proxy mode expects that
upstream to already be running. Start/Stop/Apply invoke the actual Rust engine on a serial worker
queue; Start reports success only after listener binding. Apply validates and
reloads atomically; runtime rejection preserves the old running configuration.
Quick settings edit the first proxy and listener in the JSON draft while
preserving other proxies, rules and chains. Open/Save operate on a draft; Apply
and Start save the validated profile under
`~/Library/Application Support/FlowBridge/profile.json` with restrictive file
permissions. Uninstalling the app does not remove this profile. Proxy secrets
are environment-variable references, never fields containing plaintext passwords.
A GUI process and system extension do not automatically inherit variables from
your shell; authenticated proxy secret provisioning is not implemented by this UI.
The runtime reports a missing required variable rather than inventing credentials.

## Integrated SSH and desktop workflow

The main application uses a genuine SwiftUI `NavigationSplitView` with Russian
labels: Connection, Applications, Activity and Advanced. SSH settings and connection
health are shown on the main page; JSON remains available in Advanced. There is
no shell command editor and the application does not open Terminal.

Integrated SSH exposes host, username, SSH port, local SOCKS port, optional key
and known-hosts file paths, compression, keepalive interval/count, connection and
startup timeouts, SOCKS health-check interval/timeout, reconnect backoff bounds
and maximum restart count (zero means unlimited). Defaults are 15-second keepalive,
three missed keepalives, 1-second health checks and 1–30-second reconnect backoff.
The common Rust SSH supervisor launches `/usr/bin/ssh` on macOS, uses
`StrictHostKeyChecking=yes` and `BatchMode=yes`, and supports key/agent auth.
Unknown or changed server keys and missing usable credentials are errors. The UI
can select an existing verified `known_hosts` file; it never automatically trusts
an unknown fingerprint. Secrets/passwords are not saved in desktop settings.

Desktop settings are atomically persisted with restrictive permissions at
`~/Library/Application Support/FlowBridge/desktop.json`; routing profiles remain
in `profile.json`. These files are retained when the application is removed.
Start checks that SSH SOCKS and FlowBridge ingress ports differ **before** launching
SSH, waits for supervisor readiness, then starts the engine or native capture.
A failed combined start stops the owned SSH process. Stop/normal Quit shut down
native capture, then the local engine, then SSH; unconfirmed native stop keeps
SSH alive and reports the failure.

For local SOCKS mode, the frontend updates the engine's upstream readiness gate
from supervisor status. The ingress listener remains bound during an SSH restart;
new proxied connects can wait for recovery for up to 30 seconds. Direct/Block
policy decisions are not delayed. This gate does not preserve existing TCP
connections; clients may need to reconnect. Native provider flows run in another
process and do not share this gate: new native proxied flows can fail during
reconnect. The UI explicitly distinguishes these behaviors. Seamless restoration
of established TCP sessions is outside this implementation.

In managed native mode the host inspects the actual signed `/usr/bin/ssh` binary
and supplies its observed signing identifier as an explicit Direct exemption.
This prevents the SSH transport re-entering its own SOCKS listener when its
remote port is among the captured ports. The exemption applies to all traffic
with that signing ID. Unknown-identity flows may still take Direct or Block
policy, but cannot take a proxy route while this exemption is required. Failure
to inspect the system SSH signing ID prevents managed-native startup.

## Applications and templates

The same `resources/presets.json` catalog used by the other desktop is embedded
in both app schemes. AI, Web and AI + Web cards select only discovered matches.
Discovery checks LaunchServices using catalog IDs as hints, then inspects actual
`.app` bundles in `/Applications`, `~/Applications`, and at most two levels of
subfolders. Traversal is bounded to 3,000 entries and 500 apps and does not follow
symlink directories recursively. The user may add a real `.app` manually.

Rows show the actual name, path and observed code signing identifier. Bundle IDs
and names are used only for heuristic catalog matching. Policy application IDs
come from the inspected code signature, never from catalog guesses; missing,
wildcard-containing or otherwise unsafe identities cannot generate exact app
rules. A code signing identifier is not a trust assessment. Helpers with a
different identifier are not silently added; inspect native flow activity when
checking coverage.

Selecting a preset changes a reviewable selection, not system routing. In local
mode the UI clearly states that app selection has no interception effect: only
clients explicitly configured to use SOCKS are covered. In native mode with app
selection enabled, startup uses a direct-only bootstrap until the extension is
approved, connected and reports ready. Only then does the host send generated
application rules. Selected actual signing IDs route through the selected proxy;
unmatched applications default to Direct. This template replaces the profile's
rule list, a behavior stated in the UI. Existing connections retain their policy.

The provider's live `apply_rules` message validates the complete profile, checks
readiness and requires all fields except `rules` and `default_action` to remain
unchanged. This prevents rule application from silently changing egress exclusions
or transports. The UI requires acknowledgment and guards stale operations; a
failed initial app-rule application tears down the combined start. Capture still
covers only configured TCP ports, so this is not all-protocol app tunneling.

## Signed transparent TCP application

The `FlowBridge` Xcode scheme embeds the `FlowBridgeExtension` target in
`Contents/Library/SystemExtensions`. Its product filename equals its actual
bundle identifier followed by `.systemextension`. The host identifier is
configurable via `FLOWBRIDGE_BUNDLE_ID`; extension identifier is that value plus
`.extension`. The default `org.flowbridge.FlowBridge` is an identifier string,
not a registered signing identity. Register identifiers belonging to your team.

Use your real Apple developer account, provisioned app IDs with Network
Extensions enabled, and matching installed signing identities/profiles. Set
`DEVELOPMENT_TEAM` and `FLOWBRIDGE_BUNDLE_ID` in the environment, then:

```sh
./packaging/macos/build-app.sh native
./packaging/macos/build-pkg.sh native
```

The script requires those variables; it supplies no fabricated team or profile.
Automatic signing is the default and uses the account configured in Xcode.
`ALLOW_PROVISIONING_UPDATES=1` explicitly permits Xcode to download/update
provisioning assets. For installed manual profiles, set both
`FLOWBRIDGE_APP_PROFILE` and `FLOWBRIDGE_EXTENSION_PROFILE` to their profile names;
the script selects Manual signing and sets each target separately. Set
`CODE_SIGN_IDENTITY` to your real signing certificate name when appropriate.
Entitlement files are templates: the provisioning profiles must actually grant
those capabilities. The app and extension both request
`app-proxy-provider-systemextension`; the app also requests
`com.apple.developer.system-extension.install`.

For public distribution, use Developer ID Application for code and Developer ID
Installer for the package, with the appropriate Developer ID provisioning
profiles; notarize and staple the resulting distribution using your own Apple
credentials. Xcode's Organizer export workflow can manage distribution signing.
The scripts do not submit anything to Apple's notary service. Apple requires
notarization for this system-extension distribution path. Installation and
activation remain subject to normal macOS approval/security checks.

Native outputs use `build/macos/native` and the filename
`FlowBridge-0.2.0-macOS-universal-native.pkg`.

The UI first verifies the embedded bundle identifier, valid Apple-issued code
signatures, matching Team IDs, and required entitlements. Start then submits a
real `OSSystemExtensionRequest`, displays approval/restart/error states, loads
and saves `NETransparentProxyManager` preferences, and starts its connection.
The app reports **active only after the manager is connected and the running
provider acknowledges readiness**. Signature inspection alone does not assert
provisioning, approval, notarization or readiness; macOS activation and provider
startup must succeed. Stop cancels the provider's flows. Deactivate disables the
saved configuration and requests extension removal through the OS API. Approve
any required changes in System Settings; no security settings need to be disabled.
A system extension can outlive the host process. Normal application Quit now
requests capture shutdown, then engine shutdown, then owned SSH shutdown before
completing termination. If native shutdown is not confirmed, Quit is cancelled
and the UI reports the problem. A force-killed process cannot provide that order.

## Capture scope and data path

- Capture is deliberately explicit: selected destination TCP ports, default
  `80,443`, configurable in the UI (1–64 ports, excluding DNS port 53). Apple
  restricts wildcard address rules to a concrete nonzero port. The code installs
  outbound IPv4/IPv6 included rules only for these ports. It does not claim
  complete system interception. UDP/QUIC and other ports stay direct; application
  rules cannot block uncaptured protocols/ports.
- Loopback traffic and every configured upstream proxy IP/port are excluded
  before policy evaluation to prevent self-capture. Native mode requires literal
  upstream IP addresses and rejects upstream port 53. Local SOCKS mode supports
  DNS names. Exclusions also apply to other applications contacting these
  endpoints; they intentionally take precedence over policy. Chains use the same
  exclusion list, and the Rust route guard prevents returning to the listener.
- Flow application criteria use Apple's observed `sourceAppSigningIdentifier`
  string. Empty values become JSON `null`; no executable path/PID is fabricated.
  A signing identifier is policy metadata, not independent proof of a vendor's
  trustworthiness. Path-based Windows profiles need explicit adaptation.
- Destinations use the OS-provided endpoint host. Frequently this is only an IP;
  the adapter performs no reverse lookup, fake-IP mapping or hostname inference.
  `resolved_ip` remains null when no separate resolution metadata is observed.
  Hostname rules therefore cannot reliably cover all native TCP flows. IP/CIDR
  rules are appropriate when only numeric destination metadata is available.
- Transparent mode retains normal system DNS behavior; it neither replaces DNS
  nor claims DNS-leak prevention. DNS, QUIC and UDP may bypass the TCP proxy.
- Direct returns `false`, allowing the OS to connect directly. Block closes both
  sides and returns `true`; proxy errors fail the claimed flow, never silently
  falling back to Direct. Unexpected non-TCP flow types return `false` because
  the mode expressly leaves them direct.
- Proxy/Chain opens use `fb_stream_open_json` on background queues. Each relay
  has one upload operation and one download operation; partial writes are
  handled, `-2` retries yield the worker, and the next read waits for completion
  of the preceding write. Download buffers are 64 KiB. One NE-provided upload
  buffer is retained at a time, capped at 1 MiB (larger chunks fail the flow).
  Native concurrent claimed flows are capped at `min(max_connections, 128)`.
  Both directions half-close independently; final EOF, I/O failure, idle timeout
  and stop close/cancel the handle. A stop during bounded connect closes any
  late-created handle. No socket I/O blocks a provider callback queue.
- The provider exposes bounded current/recent connection and log snapshots over
  provider messaging. Local mode polls the engine's own snapshot. Recent native
  rows/logs retain 256 entries, and runtime snapshots have their own fixed caps.
  Byte counts are observed transferred bytes, not fabricated throughput.
- Native live Apply supports rules and default action only, after provider
  readiness. Transport, exclusion and capture-port changes require Stop/Start.
  Local mode supports live Apply within the engine's reload constraints.

## Native release verification (must be performed on macOS)

1. Compile both schemes, inspect the app/extension architectures and entitlements,
   verify signatures, install the package, and verify user profile retention.
2. In local mode, start a real SSH SOCKS upstream. Exercise Start, occupied-listener
   failure, connection rows, counters, Stop, invalid Apply rollback, valid live
   Apply, profile reopen and app restart. Use a client explicitly configured for
   `127.0.0.1:1081`. Confirm enabled application rules are rejected in this mode.
3. Exercise integrated SSH with valid key/agent auth, unknown host key, changed
   key, bad user/key, occupied local SSH port, equal SSH/ingress ports, startup
   failure, process exit, health-check failure, bounded/exponential reconnect and
   manual Stop/Quit during startup. Confirm local ingress stays bound on SSH
   reconnect, new requests respect the readiness grace, old TCP sessions are not
   represented as preserved, and Existing Proxy mode clears the gate.
4. Test catalog discovery against installed and absent apps, manual bundle adds,
   names differing from catalog hints, missing signing IDs and helper processes.
   Confirm local mode has no app-routing effect, native bootstrap remains Direct
   until ready, selected IDs receive proxy policy only after acknowledgment, and
   unselected apps remain Direct. Reject transport changes in live native Apply.
5. For the native build, install into `/Applications`, request activation, test
   approval denied/pending/granted and restart-required states. No state should
   show active before provider readiness. Check the error path for invalid
   upstream hostname/port, missing provisioning and missing required secrets.
6. Capture only chosen test ports. Verify Direct/Block/Proxy/Chain, numeric IPv4
   and IPv6 flows, unknown identity, observed signing-ID rules, excluded upstream
   routes, and untouched UDP/QUIC/DNS/other ports. Use macOS Console for provider
   startup diagnostics and a packet capture when assessing actual routing.
7. Exercise upload/download simultaneously, partial writes, remote and local
   half-close, idle timeout, upstream failure, cancel during connect, many flows,
   Stop during traffic and extension deactivate. Confirm bounded resource use,
   actual closure and no recursive upstream interception.

These are release gates, not claims that they were already run. Linux checks
cover shell syntax and source/plist/project consistency only; Apple frameworks,
OS approval, packaging tools and signing cannot be validated there.

## Primary references consulted

- Apple, transparent-provider Direct semantics and DNS behavior:
  https://developer.apple.com/documentation/networkextension/netransparentproxyprovider
- Apple, included capture-rule restrictions:
  https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/includednetworkrules
- Apple, rule construction and endpoint/prefix semantics:
  https://developer.apple.com/documentation/networkextension/nenetworkrule
- Apple, flow read/write lifecycle and backpressure:
  https://developer.apple.com/documentation/networkextension/neappproxytcpflow
- Apple, source signing identity metadata:
  https://developer.apple.com/documentation/networkextension/neflowmetadata
- Apple, transparent-manager preferences:
  https://developer.apple.com/documentation/networkextension/netransparentproxymanager
- Apple, extension requests and user approval:
  https://developer.apple.com/documentation/systemextensions/ossystemextensionrequest
- Apple, extension filename/team/notarization requirements:
  https://developer.apple.com/documentation/systemextensions
- Apple, Network Extension capabilities and entitlement values:
  https://developer.apple.com/documentation/xcode/configuring-network-extensions
  https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension
- Apple, notarization and distribution signing:
  https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
- XcodeGen, target dependencies, embedding and build settings:
  https://github.com/yonaskolb/XcodeGen/blob/master/Docs/ProjectSpec.md
  https://github.com/yonaskolb/XcodeGen/blob/master/Sources/XcodeGenKit/PBXProjGenerator.swift

- Apple, native SwiftUI split navigation (macOS 13+):
  https://developer.apple.com/documentation/technotes/tn3154-adopting-swiftui-navigation-split-view
- Apple, LaunchServices-backed bundle lookup:
  https://developer.apple.com/documentation/appkit/nsworkspace/urlforapplication(withbundleidentifier:)
- Apple, reading actual code-signing identifiers:
  https://developer.apple.com/documentation/security/seccodecopysigninginformation(_:_:_:)
