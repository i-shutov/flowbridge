# Win11 native acceptance for FlowBridge 0.3.0-beta.4

Status at preparation: **NOT_RUN**. Target: Windows 11 Pro x64 build 22631 on
`VM-326272`, account `VM-326272\Admin`. Scope: internal, per-user explicit SOCKS5
with managed OpenSSH. Use the newly built beta.4 only. Keep frozen beta.3 under
`C:\FlowBridge\private-candidates\run-45986630920-1\candidate` untouched. Win10
is out of scope. Perform the test with the host's existing security policy, using
loopback fixtures and owned test processes without installing a driver or service.

## 1. Observe the host and verify the candidate

The read-only probe emits sanitized JSON to stdout. Run the host-only probe with
no arguments from the `win11-flowbridge` service runner or the target desktop.
The manual main workflow runs this mode using exact preflight source bytes, with
no checkout or uploaded artifact. The existing trusted toolchain is
`C:\FlowBridge\private-candidates\toolchain-45986630920-1\python\tools\python.exe`.

- `BLOCKED_SESSION_0` means the process cannot perform interactive acceptance.
  `active_sessions` identifies active session IDs and whether each belongs to
  Admin. Re-run from the matching, unlocked desktop to confirm that the process
  itself has access to the active input desktop. Even
  `INTERACTIVE_DESKTOP_OBSERVED` is a prerequisite observation.
- The probe inspects fixed profile locations, Programs and Start menu entries,
  registry value presence in both views, and a machine-wide process-name count.
  It avoids opening existing profile files, enumerating their contents, and
  following reparse points or registry-supplied paths. An inaccessible probe is
  a concrete blocker. Its status only describes that instant and that user.
- Before any installer, harness or candidate tool starts, obtain the standalone
  Git commit/tree and exact file SHA-256 values from the original beta.4 build
  attestation through the private handoff. Pass them as
  `--expected-source`, `--expected-tree`, `--expected-installer-sha256`,
  `--expected-manifest-sha256`, `--expected-harness-sha256`, and
  `--expected-tool-sha256`. Supply
  `--candidate-root C:\FlowBridge\private-candidates\run-beta4-<id>-<attempt>\candidate`.
  Require candidate `VERIFIED_BYTES` for the installer, manifest, harness
  and tool. The payload entries in the report are declared manifest pins.
  Verify the actual payload after install in step 3.
  Keep the original package and manifest in place. Local file hashes establish
  equality against these external pins. Repeat immediately before execution
  from the same account and protected local candidate path.

| Candidate input | File relative to candidate root |
| --- | --- |
| Original installer | `artifacts/FlowBridge-0.3.0-beta.4-windows-x64-setup.exe` |
| Original package manifest | `build/verification/explicit-beta-package.json` |
| Native smoke harness from the package's build | `build/windows-explicit-beta/Release/FlowBridgeNativeSmoke.exe` |
| Existing explicit-beta acceptance tool from the same source | `tools/explicit_beta_acceptance.py` |

## 2. Isolate the test and arrange cleanup

Use a new owner-restricted local run directory outside the candidate tree and
record a unique test ID, timestamp, account, process session and chosen test
install path. Serialize work against this user's FlowBridge namespaces. Record
the baseline for each of these fixed locations and the exact approved install
path. Keep any backups, ACLs or fingerprints of actual owner data local.

| State | Stable | Explicit beta |
| --- | --- | --- |
| HKCU settings | `Software\FlowBridge` | `Software\FlowBridgeExplicitBeta` |
| HKCU uninstall subkey beneath `Software\Microsoft\Windows\CurrentVersion\Uninstall` | `FlowBridge` | `FlowBridgeExplicitBeta` |
| Local AppData profile directory | `FlowBridge` | `FlowBridgeExplicitBeta` |
| Local AppData Programs default install subdirectory | `FlowBridge` | `FlowBridge Explicit Beta` |
| Per-user Start menu Programs subdirectory | `FlowBridge` | `FlowBridge Explicit Beta` |

Both profile directories may contain `profile.json` and
`desktop-settings.json`. Beta.4 shares the beta namespace with previous betas.
Even `/D` is overridden by an existing beta `InstallDir`. Proceed on a clean
baseline. If real prior state exists, request an isolated target account with its
own separately verified identity, or use an owner-approved same-volume escrow
with private ACL, before/after checks and a restoration owner. If reversible
isolation cannot be proven, record `BLOCKED_EXISTING_BETA`. Preserve an existing
`InstallerLanguage` value even on an otherwise clean baseline. Stop only
test-owned processes. A running owner instance blocks the test until its owner
closes it.

Avoid reading paths from pre-existing registry entries into an automated
recursive fingerprint operation without prior local path/ACL review. Record
stable before/after comparisons as booleans or limited metadata and preserve
the original data in place. Store only generated synthetic settings in the
profile used by this test.

## 3. Verify the installer and profile lifecycle

On the isolated baseline, use the original NSIS setup. For Python
`subprocess.run`, use a single raw Windows command line and
`executable=str(installer)`. The syntax is
`"<installer>" /S /D=<destination containing spaces>`. Keep `/D` last and the
destination unquoted. Check process exit and wait for registry/file completion.
Use `"<owned-install>\Uninstall.exe" /S` and wait for removal. Avoid deleting the
NSIS uninstaller by hand while a wait is pending.

1. **Install.** Use a fresh spaced Unicode path. Verify HKCU InstallDir,
   InstallLocation and DisplayVersion in the 64-bit view, as well as the three
   expected Start menu shortcuts and their targets. Reject unexpected package
   files and scope changes, including a capture helper or driver.
2. **Payload.** Check every regular file's size and SHA-256 against the pinned
   manifest without following links or junctions. Run the installed CLI's
   `capabilities` and `validate --config <installed>/examples/direct.json`
   by absolute path. Verify the explicit loopback SOCKS5 capabilities and
   observe registered install/work paths.
3. **Launch.** Use the verified GUI/harness/installed FFI from this install.
   In an interactive session, record the real window at the verified GUI PID
   and the profiles it writes, then close it. Establish hashes of the complete
   synthetic beta profile and a synthetic unrelated file at the install root.
4. **Upgrade path.** Run the same verified beta.4 installer with `/D` set to a
   different unused path. The registered location and all payload hashes must
   match, the alternate path must remain absent, and the two synthetic
   preservation comparisons must pass. This checks the registered in-place
   reinstall code path at the same version. It provides no cross-version
   migration evidence.
5. **Uninstall.** Verify the test uninstaller belongs to the registered owned
   product. Run it silently. Confirm that the payload, uninstaller,
   registration and shortcuts are removed, while the synthetic profile and
   unrelated file compare byte-for-byte. Verify the stable baseline.

The source-pinned `tools/explicit_beta_acceptance.py` can automate the core
sequence in the interactive session. Pin its bytes before invoking it. Pass
`--manifest`, `--package`, `--harness`, `--expected-source`,
`--expected-package-sha256`, `--expected-manifest-sha256`,
`--expected-tool-sha256`, `--expected-computer VM-326272`, `--execute` and
`--output` pointing to a new private results directory. The tool writes its
report and BMPs and retains owned test profile/work data, including on some
failure paths. Keep stdout in a private evidence file. Verify shortcut targets,
installed CLI validation, and final cleanup separately. A full run must report
six PASS checks for `install`, `payload`, `launch`, `upgrade`, `uninstall`,
and `stable_preserved`.

In Session 0, a separately scoped, isolated lifecycle may run install,
payload/CLI, same-version reinstall and uninstall with a **synthetic prewritten**
profile. Record any headless launch or transport results separately. The
bundled acceptance tool couples launch and BMP capture, so use the ordered
checks above for a headless subset. Leave desktop launch, keyboard, visual and
GUI-driven SSH cases blocked until an interactive session is available.

## 4. Exercise the installed GUI and real SSH

Use the same exact candidate in a second fresh owned install or before the
manual lifecycle uninstall. Recheck all pins and closed, isolated baseline
after removing prior synthetic state. Record WTS session, screen size and
scaling, window geometry, expected HWND/PID and foreground ownership. Capture
the actual foreground app and check monitor bounds, content, keyboard focus,
Tab/Enter, Apply/Save/Cancel and Start/Stop. Cover Dashboard, SSH, proxy,
applications and advanced views at normal and compact geometry. Keep images
and timestamped UI actions under the private run directory. Distinct BMPs from
the native harness support geometry checks. A person or desktop automation must
observe the actual rendered controls, text and focus for visual acceptance.

Use a loopback-only standalone `sshd.exe` process and Python echo receiver
with independent accepted-connection counts. Verify Microsoft Authenticode
`Valid` on the local fixture binaries and record their SHA-256. Use unique
ephemeral host/client keys, `authorized_keys`, and pinned `known_hosts` in a
private subdirectory. Validate a separately scoped sshd config and listen on
`127.0.0.1` with public-key auth and forwarding limited to the loopback echo
destination. Use disjoint ingress, worker SOCKS, sshd and echo ports. The existing
`tests/windows_installed_real_ssh.py` on the candidate source offers a fixture
recipe and retains its original hosted-scope guard. If a trusted fixture cannot
start under the existing configuration, record that prerequisite as blocked.

Bind automation to the pinned installed GUI PID and verify each live control
before use. Candidate source has Start/Stop 100/101, Journal 111, SSH health
210, managed selector 230, host/port/user 231/232/233, identity/known_hosts
234/235, Save 240, SSH summary 272, remote DNS 285, OpenSSH executable 286 and
worker count 288. Adjacent worker listeners are spaced by two ports. Use a
managed proxy as the tested route with the echo reachable by a hypothetical
direct connection so the echo counter can catch fallback.

| Case | Required observation |
| --- | --- |
| Healthy | Live managed Ready and test-owned Microsoft OpenSSH child with matching image hash. Reach the echo through the FlowBridge ingress using SOCKS5 `ATYP=DOMAINNAME`. Verify binary nonce bytes and both EOF directions. Record a positive accepted-connection increment. |
| Wrong host key | Replace the fixture's correct pinned host key with another valid fixture key. Observe failure or retry without Ready, no successful SOCKS connection, zero echo accepts. Restore the correct pin and repeat the positive control. |
| Absent private key | Use an absolute, missing fixture key with other test fields correct. Observe a validation rejection or managed start failure, no Ready for the invalid configuration, zero echo accepts. Restore fixture key and repeat healthy traffic. |
| Untrusted backend and privacy | Use a benign unsigned test executable as the explicitly selected backend. Require trust rejection before spawn, no fallback, zero echo accepts, and only a sanitized error category in status/Journal. Check locally for raw stderr, username, key and backend paths, then record the redaction result without the sensitive text. Restore the signed backend and reconfirm traffic. |
| All-down and recovery | Stop only the test daemon and its identified test connection workers. Observe managed readiness go to zero and test a fresh SOCKS connection after the gate closes. Require zero echo accepts, then restart with the same host key and verify a fresh nonce and EOF again. |
| Stop | Observe GUI Stop, closed ingress and worker sockets and no surviving owned SSH child. Close the GUI and confirm its PID is gone. |

For negative tests distinguish TCP refusal or timeout from an actual received
SOCKS reply. Record `rep=null` when no SOCKS reply arrives. Start each negative
case with a known test state so a prior healthy GUI route cannot mask a rejected
edit. A single failure case run is separate from the managed aggregate
512-flow acceptance run.

## 5. Restore and retain evidence

Use a cleanup path on success and failure. Wait for test-owned GUI, harness,
SSH child processes, fixture and listeners to stop. Run only the verified
test-owned uninstaller if still installed. Remove the generated synthetic data
and fixture keys only after confirming path and ownership. Restore any escrow
and exact pre-existing beta/stable state. Recheck applicable HKCU and files,
ACLs, process/listener baseline and the frozen candidate's original pins. Record
a cleanup failure even if the functional checks passed.

Keep the original preflight, lifecycle/SSH case JSON, native and desktop images,
action history and restore report private. Provide an evidence manifest of
member hashes and sizes and verify any private archive CRC and SHA-256. Exclude
keys, profiles, raw process output, command lines containing secrets, real user
paths and production endpoints. Use sanitized summaries in workflow logs.
Report each case as PASS, FAIL or BLOCKED with the exact source, candidate, host
and evidence pins. Claim native functional and visual acceptance only once all
their respective checks and restoration are evidenced. A5/A6/A7 and WFP/G2
remain separately decided.
