# R5 prerequisite: conservative protected-route verdict (offline)

**Date:** 2026-10-31. **Base:** PR #54 HEAD `ef253061a44479be478b7ed286def77957d3bc0f`. This is a new, separate clean-room Rust module improvement, not a production capture path. Windows Server 2025 CI cannot establish native Windows 10/11 interception or DNS leak-freedom.

## Threat and policy distinction

The older `CapturePolicy::route` is a general-purpose policy suggestion, optionally permissive about unknown owners and selected-app UDP. It also treats a filename alone (e.g. any `ssh.exe`) as a carrier exemption. **None of those shortcuts is acceptable for protected capture.** A malicious or merely unrelated executable can be renamed; a basename is not proof of the exact supervised SSH process. An IP Helper PID candidate or a process path alone is likewise not packet ownership attestation.

The new `CapturePolicy::route_protected` is an explicitly stricter, offline candidate verdict. It rejects unknown/malformed owner identity, unsupported UDP (including selected-app DNS/QUIC) and basename-only carrier exemptions even when the ordinary capture policy was constructed permissively. Known unselected executables remain on the normal DIRECT path; this is an architectural decision for selected-app mode, **not** proof of DNS isolation when an OS resolver or child service sends on behalf of a selected application.

The protected verdict allows a TCP `Proxy` *candidate* only when all five supervisor-provided conditions are true: (1) verified driver tunnel mode, (2) fresh OS owner attestation, (3) live supervised SSH/SOCKS upstream, (4) independent DNS/UDP containment, and (5) rollback/fail-closed guard armed. Each false or missing prerequisite blocks selected TCP. The readiness struct is data, not a cryptographic token, and its booleans must never be writable by ordinary UI/IPC clients. It currently performs **no** privileged OS check, packet filtering, driver mode change, or routing itself.

Actual trusted-carrier handling is deliberately excluded: a future independent native supervisor must bind the exact launched SSH PID, process creation time, executable identity, and service-session identity, then safely exempt that traffic without basename matching or uncontrolled DIRECT fallback. Until such identity-aware exemptions and rollback are proven, **do not enable protected mode**.

## Regressions and acceptance

Unit tests enumerate all 32 readiness combinations under an otherwise permissive policy, asserting that selected TCP cannot become Proxy with any missing guard; selected UDP and unknown owners always block; unselected attested identities remain direct. A separate spoofing regression verifies that arbitrary `ssh.exe`, `FlowBridge.exe` or `ProxiFyre.exe` paths are *blocked* in the new protected verdict even though the normal legacy verdict labels them `Carrier`. No test is disabled or softened.

### Still open

- Native read/write NDISRD IOCTLs, adapter-mode ownership and revert-on-failure, bound queues and cancellation.
- Verified packet-to-process binding under PID reuse, canonicalized executable paths, actual selected-app TCP bridge via FlowBridge SOCKS → SSH.
- Demonstrated in-kernel selected-app UDP/DNS containment, resolver attribution, DoH/DoT, IPv6/QUIC, leak pcap and failure-injection.
- Win10 22H2/Win11 x64 with separately installed officially signed NDISRD, protections enabled; recorded exact commit, binary SHA and packet traces. A native test is mandatory to claim protected fail-closed or DNS leak-free.

Source of external driver semantics: official vendor documentation at <https://www.ntkernel.com/docs/windows-packet-filter-documentation/>. No ProxiFyre implementation is used.
