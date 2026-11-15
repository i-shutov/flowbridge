# R02/R06 — Scope macOS managed SSH carrier bypass to verified identity AND exact remote socket

Date: 2026-11-15. Functional product change stacked on Draft PR #63.
Does NOT modify frozen explicit SOCKS beta, Windows NDISRD/WFP, main, host security, or deploy a signed extension.

## Confirmed defect in existing product source

Prior `TransparentProxyProvider.handleNewFlow` did:

    if bypassSigningIDs.contains(flow.metaData.sourceAppSigningIdentifier) { return false }

This returns DIRECT for **every** flow attributed by macOS to the `ssh`
signing identifier, irrespective of its destination or source process instance.
Even when a selected application policy says Block/Proxy, the signing-ID
exception wins. `DesktopController` derived that identifier from the signed
`/usr/bin/ssh`, but it did not bind the exception to its managed connection.
Therefore a second unrelated `/usr/bin/ssh` invocation can use the carrier
exception, instead of being evaluated by selected-application routing.
This is a reproducible source-level bypass rule; no physical leak claim.

## Product fix / trust boundary

- `DesktopController.start` now requires an explicit **literal SSH server IP**
  and valid SSH server port for transparent integrated SSH, not an arbitrarily
  resolved host name. It passes exact `sshTransport` IP+port along with the
  OS-verified `/usr/bin/ssh` code-signing identifier.
- `NativeController.start` refuses a managed-SSH exemption with missing,
  duplicate or unverified signing IDs, missing transport endpoint, or a
  bypass list when no managed SSH is active. It serializes the exact
  transport endpoint into providerConfiguration.
- The **system extension itself** inspects `/usr/bin/ssh` using Apple
  `SecStaticCodeCreateWithPath`, a valid `anchor apple` requirement,
  `SecStaticCodeCheckValidity`, and original Apple signing information;
  it does not accept an arbitrary claimed bypass identity from a mutable
  user-facing profile.
- The extension compares the **OS-observed** flow signing ID, the canonical
  literal IPv4/IPv6 address bytes and exact TCP destination port together.
  It returns `false` (system DIRECT) only on **all three** exact matches;
  wrong host, wrong port, wrong source app and unknown signing ID are not
  automatically bypassed. Unknown signing ID is conservatively blocked
  when a managed transport exclusion is configured.
- IPv6 compressed/expanded forms are compared as 128-bit bytes. IPv4 and
  IPv4-mapped IPv6 are *not* treated as equivalent without independent
  physical normalization proof. Dynamic DNS names cannot mint a trusted
  exception, deliberately refusing to start rather than silently opening
  a whole-app DIRECT exemption.

## Actual scoped test suite

The existing real-provider Swift lifecycle harness compiles the production
method bodies with **test-only Apple/FFI shims**. A build flag
`FLOWBRIDGE_PROVIDER_TEST` injects only the simulated system SSH identity;
production code instead invokes real Apple Security. The standard macOS
application/extension CI separately typechecks the real Security.framework
code against Apple SDK.

Added 9 deterministic carrier scenarios:

1. Correct Apple SSH signing identity + exact IPv4 server IP:port bypasses
   (carrier stays usable even if ordinary app policy would Block).
2. Same signing ID targeting another IPv4 host must be evaluated/blocked.
3. Same IP but a different TCP port cannot bypass.
4. Unrelated application signing ID to the server IP cannot bypass.
5. Missing signing ID fails closed in managed transport mode.
6. Canonical equivalent IPv6 textual forms match, different IPv6 does not.
7. IPv4-mapped IPv6 cannot mint a second unproved IPv4 exemption.
8. Fake signing ID is refused at startup before settings apply.
9. Absent hostname/transport, DNS hostname, invalid port, duplicate IDs,
   no managed transport and failed trusted identity all deny startup.

Negative acceptance includes old-source reproduction of **other SSH
destination escaping DIRECT**, and two deliberate mutations: one removes
the exact endpoint check, the second replaces trusted Apple signature
verification with an arbitrary nonempty signing ID. A pass means these
mutations fail for the intended reasons. The earlier R02/R06 Start/Stop,
policy Apply and stale DIRECT tests continue unchanged.

## Remaining unavoidable native security boundary

- A signed app/extension must be provisioned and installed on real Mac
  Apple Silicon AND Intel with the approved NE entitlement and Apple
  deployment policy, and actual SSH+IPv4/v6 egress records captured.
- This creates a **narrower** exception, not process-instance attestation.
  Another genuine `/usr/bin/ssh` connecting to the *same* server IP+port
  has the same signing ID and destination, and cannot be distinguished
  by this evidence. An OS-issued per-process SSH supervisor binding or
  kernel-level provenance would be required to close that subcase.
- `NEAppProxyFlow.metaData` may be incomplete; unknown identity is denied
  in protected transport mode. Actual system NE rule/port matching,
  SSH restarts, sleep/wake, DNS/UDP/QUIC and physical no-DIRECT still OPEN.
- The signed developer identity / entitlement and physical native R02/R06
  are not accepted. R01/G2 Windows remains NO-GO.

**Release verdict remains false:** no original owner native A3/A4 acceptance,
no protected flow G2 PacketBound, no signed NE R02, no 1.0 or beta release.

## Source references

- `native/macos/App/DesktopController.swift`
- `native/macos/App/NativeController.swift`
- `native/macos/Extension/TransparentProxyProvider.swift`
- `tests/macos_provider_lifecycle.swift`
- `tests/macos_provider_test_shims.swift`
- `tools/test_macos_provider_lifecycle.py`
- Original product parent: Draft PR #63, exact SHA `7aade6a3a496306fa069e607cdb6e28ef859abdb`
