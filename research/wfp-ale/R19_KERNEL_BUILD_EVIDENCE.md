# G2 R19 — first original Rust kernel observer compiled; NOT loaded or accepted

2026-11-07. Research branch `research/windows-wfp-ale-attribution-20261107` only.
Owner explicitly authorized a new kernel backend and push-trigger execution.
That does not waive signature, independent current VNC, SYSTEM rescue, firewall/
Defender, SecureBoot/MemoryIntegrity, exact-source and rollback gates for loading.
Beta/PR #56/main, other servers, runner labels and automations are not changed.

## Delivered result

An original Rust `no_std` WDM observer is now a real linked x64 Native PE `.sys`,
not a Python trust model or a filename-only mock. Code/runtime is Rust plus
Windows kernel libraries. WDK C headers generate ABI bindings at build time;
no copied ProxiFyre code, C++ WFP payload or vendor driver is linked/distributed.

The source registers process-create/delete callbacks and IPv4/IPv6 ALE callouts.
At observed process creation it references the supplied EPROCESS and executable
FILE_OBJECT, retains creation epoch and PsGetProcessStartKey from that object,
and stores a full downcased creation image path. It does not query the numeric
PID later to manufacture a process identity. Unknown/pre-existing/dead processes,
reused PIDs, missing fields, exact image/AppId mismatches and capacity overflow
are denied as sources of positive observations. Observations use the SAME ALE
callback's PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE and APP_ID. A restricted
SYSTEM/admin device IOCTL returns bounded candidate receipts without pointers.

**This is an observer, not transparent routing.** It registers no BFE filters,
applies no redirect, and only returns CONTINUE. Without separately installed lab
filters its ALE callback receives no selected classifications. No G2 PASS,
PacketBound, protection from DIRECT or release is asserted. The process ledger
is intentionally bounded to 256 lifetime owners and 32 queued observations;
it has no eviction/recovery policy suitable for a general product.

## Exact build and execution evidence

| Item | Value |
|---|---|
| Source built | `b8fc020cf5ada3c989ef9a406021bf44012fb78f` |
| GitHub Actions run | `42381023741`, attempt 1, two jobs SUCCESS |
| Build-only job | `128428469422` |
| R17 user-mode socket job | `128428469239` |
| Kernel artifact ID | `13577538218` |
| Kernel ZIP SHA256 | `83f214791b55d34c079f3903449a1dae7f5132fd7fcf0e5a9dcaee89ebae3bb6` |
| Socket artifact ID | `13576609950` |
| Socket ZIP SHA256 | `58efe756f2642eb82b3a2ca2166713bba1eb87cf050f2feb29c5c9ca1c5cdc72` |
| Original .sys bytes | 198144 |
| .sys SHA256 | `a48d6122a158de3a2cf912e5f8bc6d6eacf6bee5dde09fada3fbdaaa22ff5acc` |
| Toolchain observed in job | rustc 1.99.1, MSVC x64; WDK NuGet 10.0.26100.6584 |

Both ZIPs were downloaded, their digests compared with the authenticated GitHub
artifact API, and CRCs verified. The native PE was **never loaded or executed**
by the independent reader. An independently written standard-library parser
(not workflow `pefile`) checked section bounds, entrypoint, x64/Native format,
FORCE_INTEGRITY/NX/DYNAMIC_BASE, lack of W+X sections, and exact imports.
Runtime import libraries: ntoskrnl.exe, fwpkclnt.sys, hal.dll. Required callback,
process time/startkey and object-reference functions are really imported.
Embedded certificate directory is empty and no signed catalog is supplied.
**FORCE_INTEGRITY is a header bit, not a signature and not load acceptance.**

The actual `ledger.rs` used by the driver was also compiled and executed as a
user-mode test binary on Windows: **11 passed, 0 failed, 0 ignored**. These tests
exercise the source logic, not kernel callbacks or kernel scheduling.
Independent local artifact-reader tests: **15/15 PASS**, including deliberate
PE-machine/subsystem/entry/import/section/digest tampering and signature/scope
misinterpretation controls. No independent human reviewer is claimed.

Build warnings remain visible: 10 generated-bindings unnecessary-transmute
warnings and one LNK4216 exported-entry warning. No strict all-warnings-clean
or runtime kernel-safety claim. Cargo.lock and generated WDK ABI are retained in
the original artifact. The first successful build still generated the lockfile
and selected the hosted SDK/toolchain: byte-reproducible rebuilding and a frozen
compiler/SDK/action dependency chain are not yet established.

## Concrete build failures and causal fixes (no failed run was rerun)

| Source / run | Failure | Next-source correction |
|---|---|---|
| 55ed77a5 / 42379335275 | WDK networking types unavailable to bindgen | NDIS630 + official ndis.h |
| f9b49368 / 42379863886 | Generated WDK enum widths/callback ABI and Unicode declaration | Correct x64 generated types, extern C callbacks, ntifs.h |
| f4cde8c8 / 42380562269 | Only MSVC no_std symbols _fltused / __CxxFrameHandler3 unresolved | Original linker marker and abort-only unexpected-unwind handler |
| b8fc020c / 42381023741 | Build + exact ledger tests + static audit SUCCESS | Current compiled checkpoint |

The no_std ABI support follows the documented need for these compiler symbols
in Microsoft's windows-drivers-rs. It does not link a user-mode exception runtime
or return a fake-success exception disposition. Unexpected panic/unwind causes
a bugcheck; this is one reason native driver loading is not yet appropriate.

## R17 finally measured on real Windows (separate from the new kernel)

The user-mode Rust R17 module compiled and its two tests executed. The independent
Python native reader queried caller-owned IPv4 and IPv6 loopback TCP sockets:
SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE -> FwpsAleEndpointGetById0 -> AppId.
Client and accepted socket endpoint IDs were different, AppIds equal as expected
for this same-process experiment. All owned sockets and query sessions closed.
Both redirect-record/context IOCTLs reported error 10022. **Query error is not
proof of absence**, and these results do not identify a remote original process.
No unprepared EXE, selected-app routing or packet redirection was tested here.

## Precise remaining native/G2 gates

1. Review and resolve kernel lifecycle/IRQL/rundown/unload correctness, supported
   process-birth coverage, path alias mismatch behavior, session uniqueness and
   security-cookie/entrypoint/HVCI requirements. Compiling does not prove these.
2. Implement the actual owned redirect context/record binding to the accepted
   proxy socket, and independent origin/negative trace verification. It is not
   implemented in this observer. NDISRD per-frame identity does not follow from it.
3. Obtain an accepted kernel signature for the exact package, without disabling
   protections or using test-signing as an undeclared workaround. No signing
   credentials/Hardware Dev Center submission were used; no purchase was made.
4. On the authorized isolated test machine, establish actual recent VNC proof,
   independent SYSTEM rescue, exact source/binary hash, Defender/firewall and
   rollback before load; native Win10/11 acceptance cannot be inferred from the
   hosted Server2025 build. No new VNC observation was fabricated.
5. Execute original EXE/sibling, process death/PID reuse, IPv4/IPv6, stale endpoint,
   absent/foreign redirect context, SSH/WFP failure and no selected physical
   DIRECT tests with independent evidence. Existing G1 dd1ab3c is not transferable.

No new authorization to *create* the backend is needed; that was granted. The
missing state is accepted signature, verified native safety prerequisites and
completion/verification of the actual redirect linkage. `g2_pass=false` and
`release_accepted=false` are retained. This is substantial kernel implementation
and build progress, not a declaration that G2 is finished.

## Offline reproduction

The original ZIPs accompany the downloadable R19 checkpoint; they are not
installed by the verifier. From a checkout:

```sh
python research/wfp-ale/verify_kernel_r19.py KERNEL.zip SOCKET.zip
FLOWBRIDGE_R19_KERNEL_ZIP=KERNEL.zip FLOWBRIDGE_R19_SOCKET_ZIP=SOCKET.zip \
  python -m unittest discover -s research/wfp-ale -p test_verify_kernel_r19.py -v
```

Primary sources:
- https://github.com/i-shutov/flowbridge/actions/runs/42381023741
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessstartkey
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-
- https://github.com/microsoft/windows-drivers-rs/blob/main/crates/wdk-sys/src/lib.rs
