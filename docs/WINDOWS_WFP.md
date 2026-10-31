# FlowBridge Windows TCP capture implementation

Updated 2026-10-28. This is an **original, reviewable native capture implementation**, with a cross-compiled user-mode service and WDK driver sources. It is **not a signed or runtime-validated Windows driver release**. The normal desktop installer must continue to leave transparent capture unavailable until the gates below pass. No `.sys` or `.cat` is fabricated; neither test-signing nor disabling Windows integrity checks is part of this delivery.

## What is implemented

| File | Responsibility |
|---|---|
| `native/windows/wfp/driver/driver.c` | IPv4/IPv6 ALE connect redirect callouts, trusted process metadata capture, redirect-state checks, exclusive administrative device, owner-bound IOCTL configuration |
| `native/windows/wfp/driver/FlowBridgeWfp.vcxproj` | Windows 10/11 x64 WDM build using Microsoft's WDK |
| `native/windows/wfp/driver/FlowBridgeWfp.inf` | Demand-start primitive driver package source; catalog signing is a separate release step |
| `native/windows/wfp/control.h` | Versioned device configuration/status ABI and project-owned provider/sublayer/callout GUIDs |
| `native/windows/wfp/redirect_context.h` | Version 2, 2112-byte trusted per-connection metadata record |
| `native/windows/wfp/redirect_io.cpp` | Accepted-socket context/opaque-record query and outbound pre-connect record assignment helper |
| `native/windows/wfp/capture.cpp` | Dynamic WFP engine session; transactional provider, sublayer, callouts, capture/bypass filters; automatic rollback |
| `native/windows/wfp/service.cpp` | SCM/console entry points, native listeners, validated profile loading, bounded stream relay through Rust FFI |
| `native/windows/wfp/CMakeLists.txt` | Independent user-mode service build; no installation or automatic activation target |

The service calls `fb_stream_open_wfp_json(config, flow, records, length)`. The core applies policy and creates the outbound route with the supplied WFP records set **before** every outbound connect attempt. Direct routes, initial proxy hops, and retry addresses all require this operation. The existing stream read/write/half-close/close API carries application bytes. There is no path that falls back to an unrecorded or direct connection after a proxy or record-setting error. Microsoft requires associating the original and outbound sockets through these records [1, 4, 5].

The kernel contains no JSON parser, proxy credentials, DNS resolver, network relay, UI code, or application-name rule matcher. Its work is limited to native metadata capture and local redirection. The service and Rust core own application rules and routing.

## Lifetime and ordering

1. The service reads a bounded profile, rejects embedded NUL bytes, and calls the common profile validator. Its administrator-controlled executable, profile and parent directories are deployment requirements.
2. Winsock starts. Separate IPv4 and IPv6-only loopback listeners bind ephemeral ports with exclusive address use. Both must succeed; a partially available family does not report Ready.
3. A fixed worker pool starts. The service admits at most `min(profile.max_connections, 32)` accepted connections in total, including queued connections and active workers. An admission above this bound is closed. A worker can create one upload thread for its current connection, giving at most 64 relay threads at the 32-flow native cap.
4. The service opens the exclusive driver device. Its ACL admits SYSTEM and local administrators. Query checks exact ABI version, struct size, and the requestor-derived service PID. The caller cannot supply an arbitrary proxy PID.
5. A dynamic WFP session opens and one transaction creates the FlowBridge provider, sublayer, two callout-management objects, TCP capture filters, and higher-weight executable bypass filters. A callout query verifies that both kernel callouts are registered. Existing colliding project GUIDs produce startup failure, not deletion of unknown objects.
6. The owner-bound configuration IOCTL publishes the two already-listening ports. The WFP transaction commits. Only then does the service publish SCM Running and a `ready` log event.
7. On stop or failure, the service closes its dynamic WFP session first, disables driver admissions, and closes the driver handle. Queued connections close and workers terminate through bounded I/O polling and the core's bounded open deadline. Listeners and Winsock outlive this cleanup.

No persistent or boot-time capture filters are installed. Dynamic objects are tied to the management session [6]. Driver device cleanup disables capture if the owner handle closes. A service crash therefore removes capture and restores normal OS routing after cleanup; **this is not a system kill switch**. Already proxied connections fail when their service process exits. The driver is demand-start, not boot-start.

SCM stop is observed by the accept loop and pumps at approximately 200 ms polling intervals. A worker already establishing an upstream route can remain inside the core's open deadline of up to 30 seconds; no claim of immediate cancellation of that phase is made. There is no unauthenticated control pipe or network API. Profile changes require a service restart in this version; GUI service control, status IPC, credential storage, and recovery configuration remain separate release work.

## Kernel classify invariants

Both callouts register through `FwpsCalloutRegister1`, with the version-1 classify signature needed for connect redirection [1]. Filters match TCP; the classify function independently verifies TCP. UDP, QUIC, ICMP, and other protocols are untouched.

The function checks `FWPS_RIGHT_ACTION_WRITE` before changing the result. Driver configuration is copied under a spin lock and all WFP API calls occur after releasing that lock. There are no pended classifications, per-flow kernel contexts, pageable allocations, or worker items. All application-context bytes are initialized before transfer to WFP.

Self-originated service connections bypass capture. If redirect-record metadata exists, the driver queries the redirect state using its own redirect handle. Self, previously-self, and other-provider redirection states are passed through without another redirect. Respecting another provider reduces coverage; it avoids pretending that another proxy's endpoint is the original destination. The writable request's previous local redirect handle is an additional coexistence check [1, 2].

Every successful `FwpsAcquireClassifyHandle0` is matched by a release. Every successful `FwpsAcquireWritableLayerDataPointer0` is matched by `FwpsApplyModifiedLayerData0`, including paths that decide against modification [3]. Writable acquisition clears action-write rights; permitted paths restore soft-permit arbitration unless the filter explicitly requests `FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT`. This does not create an authorization-layer firewall exemption.

A redirect allocates a nonpaged application context, copies the original sockaddr information, fills the trusted source identity, and changes only the remote endpoint plus documented redirect fields. `localRedirectTargetPID` is the device owner's PID and `localRedirectHandle` is the cached WFP handle. WFP owns the pool allocation after the modified request is applied [7]. Earlier failures free it locally. Failures in capture metadata/allocation/handle acquisition block that attempted connection.

Driver unload disables new work, unregisters the two callouts before destroying the redirect handle, and deletes its device/link. There are no attached flow contexts that require asynchronous deletion callbacks. Windows stress and Driver Verifier must still validate callback/unload concurrency; cross-compiling user-mode code cannot prove it.

## Trusted identity and ABI v2

The connect-redirect layers do **not** list `FWPS_METADATA_FIELD_PROCESS_PATH` as available metadata. They do supply PID metadata, and the layer's `ALE_APP_ID` field supplies the application path [8, 9]. The driver copies that kernel-supplied UTF-16 path at classification time. It does not ask user mode to rediscover the process by PID.

Consequently, a process exiting or the OS reusing its PID cannot cause a later process's path to be substituted into an accepted connection. PID and `flow_id` are diagnostic values, not authorization tokens. A binary signature or publisher identity is not asserted.

Context v2 is exactly 2112 bytes, with these offsets:

| Offset | Data |
|---|---|
| 0 | Magic, version, exact size |
| 8 | Original process ID, 64 bits |
| 16 | Driver-generated correlation ID, 64 bits |
| 24 | Address family and original network-order port |
| 28 | Original address, 16 bytes; IPv4 uses the first four |
| 44 | IPv6 scope ID |
| 48 | UTF-16 code-unit count, excluding terminator |
| 50 | 14 reserved zero bytes |
| 64 | 1024 UTF-16 code units, including zero terminator and zero tail |

Scalar fields have Windows native little-endian representation; addresses/ports retain network order. Both driver and service enforce path bounds. The user-mode query rejects unknown versions, wrong sizes, invalid families, missing PID/port, nonzero reserved bytes, invalid IPv4 padding, embedded control characters, missing path termination, and nonzero tail data. UTF-16 conversion rejects invalid surrogate sequences before policy evaluation. Opaque WFP records are bounded to 64 KiB and never parsed.

The current core's `application` field means an executable **basename** (for example `chrome.exe`). The service derives it from the captured path and logs the full kernel path. Thus existing application patterns work, but basename rules do not distinguish two different binaries named `chrome.exe`; full-path/publisher authorization is not implemented. Paths over 1023 UTF-16 units are rejected, not truncated. A plain loopback connection without valid WFP context and records is rejected.

Version 1's earlier 64-byte ABI is intentionally incompatible. A v1 driver must not be paired with this service. The query handshake and per-flow exact version checks enforce that boundary.

## Loop avoidance and local SSH proxies

There are three distinct protections: the owner PID bypass in the driver, an explicit service executable bypass filter, and WFP redirect-state checking with opaque-record propagation on the upstream socket. The latter remains mandatory even with the first two protections.

Any separate local proxy transport process also needs an administrator-selected executable bypass. For example, `ssh.exe` connecting to the SSH server must not itself be routed back through the SOCKS endpoint that it provides. Pass its **absolute executable path** through `--bypass`. The service resolves that path using `FwpmGetAppIdFromFileName0`; it does not use an untrusted process name to authorize bypass. There are at most sixteen bypass paths including the service itself.

Each bypass is a separate higher-weight permit filter in FlowBridge's sublayer. Repeating `ALE_APP_ID != path` conditions in one filter is deliberately avoided because repeated-field matching semantics can make exclusions incorrect. A bypass applies to every process running the selected executable and takes precedence over FlowBridge's routing rules. It does not override other providers' authorization policy. Review that scope when selecting an SSH or VPN transport executable.

## Build and validation performed

In the Linux build environment, all three user-mode C++ translation units (`service.cpp`, `capture.cpp`, `redirect_io.cpp`) were compiled for x86-64 Windows with MinGW C++17 and `-Wall -Wextra -Wpedantic -Werror`. The resulting objects linked successfully as `FlowBridgeCapture.exe` against the Windows Rust FFI import library, `fwpuclnt`, `ws2_32`, and `advapi32`. This proves source/API/link consistency for that SDK, **not execution on Windows**.

Older MinGW headers omit the three redirect IOCTL definitions and several WFP GUIDs/flags. The source supplies their Windows SDK values in guarded compatibility declarations. Microsoft SDK builds use their native declarations. The kernel is never compiled against guessed user-mode WFP types.

Build the user-mode service from a Visual Studio developer shell, after building the matching Rust Windows FFI library:

```powershell
cmake -S native/windows/wfp -B build/wfp-service -A x64 `
  -DFLOWBRIDGE_FFI_LIBRARY=C:/absolute/path/flowbridge_ffi.lib
cmake --build build/wfp-service --config Release
```

An import-library build also needs its matching `flowbridge_ffi.dll` beside the service executable. A static-library build needs the platform dependencies listed in CMake. A MinGW build needs a Windows toolchain file and the `.dll.a`/`.a` equivalent. The canonical release toolchain is Microsoft's supported SDK/WDK.

Build driver source on Windows with Visual Studio 2022 and the Windows 10/11 WDK:

```powershell
msbuild native/windows/wfp/driver/FlowBridgeWfp.vcxproj `
  /p:Configuration=Release /p:Platform=x64
```

The project turns on warnings as errors and buffer security checks. It does not sign the driver. WDK compilation, INF validation, catalog generation, signing and runtime loading have **not** been performed in this environment.

After a signed, validated driver package is installed in an isolated Windows test environment, the service has explicit console and SCM modes. An example console command is:

```powershell
.\FlowBridgeCapture.exe --console `
  --profile C:\ProgramData\FlowBridge\capture.json `
  --bypass C:\Windows\System32\OpenSSH\ssh.exe
```

SCM launches the same binary with `--service --profile ...` and the same required bypasses. The service name is `FlowBridgeCapture`. A production registration must use a quoted absolute executable path, protected configuration directories, a deliberately chosen service identity and dependencies, and audited service ACLs. This source delivery does not install or launch the service. It does not change machine driver policy.

## Remaining functional boundaries

- Only **new outbound TCP connects** are captured. Existing sockets are not migrated.
- IPv4 and IPv6 connect redirection are implemented. Nonzero IPv6 destination scope IDs are explicitly rejected because the current Rust endpoint ABI cannot preserve zones. Connections explicitly bound to non-loopback local addresses require Windows tests for TCP/IP zone-crossing behavior; the current target listener is loopback [1].
- Transparent connect redirection yields an IP address, not a trustworthy hostname. No DNS interception, DNS leak prevention, hostname reconstruction, DoH handling, or QUIC filtering is asserted.
- Other providers' redirected flows are bypassed. Coexistence is conservative and is a coverage boundary, not complete multi-proxy composition.
- ApplicationContainer/UWP behavior, alternate network compartments, VPNs, EDR/firewall products and restricted users require native verification.
- Service readiness verifies bindings, profile, ABI and kernel registration; it does not yet execute an end-to-end redirected self-test. The desktop GUI therefore must not infer transparent readiness merely from these source files or a compiled service.
- The management path is SCM/administrative command line, not integrated GUI status/control. Deployment least privilege, policy reload, secure credential provision and recovery settings remain release requirements.

## Required Windows gates before enabling the installer/UI

1. Compile the WDK project with the chosen release WDK, validate INF/catalog, review static analysis, and obtain applicable Microsoft driver signing. Keep Secure Boot and integrity policy intact [10].
2. Test direct, block, SOCKS5, SOCKS4a, HTTP CONNECT and chain routes with local test endpoints. Verify that no failed route produces direct traffic. Record packet captures and expected policy decisions.
3. Verify trusted executable path/PID/original destination for IPv4, IPv6, IPv4-mapped addresses, rapid process exit/PID reuse, Unicode paths, protected processes and malformed/unredirected listener clients.
4. Verify record propagation on every first-hop/address retry, self bypass, local SSH bypass, other-provider redirects and inbound authorization. Check that firewall blocks still prevail.
5. Stress simultaneous connections and cap saturation, bidirectional backpressure, half-closes, idle timeouts, stopped readers, resets, proxy failure, service stop during open, service crash, driver unload, BFE restart and repeated start/stop.
6. Run Driver Verifier with appropriate WFP/network verification, pool/IRQL/deadlock checks, leak analysis and crash-dump review in an isolated supported VM. Include memory pressure and active-flow unload.
7. Validate installation, ACLs, signature failure, declined permissions, upgrade/rollback/uninstall, and recovery after reboot. Only the signed passing package may be registered by a transparent-mode installer. Keep the standard SOCKS-only installer independent.

## Primary references

1. Microsoft, [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection).
2. Microsoft, [Using Proxied Connections Tracking](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking).
3. Microsoft, [FwpsAcquireWritableLayerDataPointer0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0) and [FwpsApplyModifiedLayerData0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0).
4. Microsoft, [SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context).
5. Microsoft, [SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records).
6. Microsoft, [Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management).
7. Microsoft, [FWPS_CONNECT_REQUEST0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0).
8. Microsoft, [Metadata fields at each filtering layer](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer).
9. Microsoft, [FWPS_FIELDS_ALE_CONNECT_REDIRECT_V6](https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ne-fwpsu-fwps_fields_ale_connect_redirect_v6).
10. Microsoft, [Kernel-mode code signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-).
