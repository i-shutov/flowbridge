# R45 — One-shot ARM source finding and restart NO-GO

Date 2026-11-08. Only research/windows-wfp-ale-attribution-20261107. Not beta, PR 56, PacketBound/G2, native proof or leak-free certification.

Exact branch parent: d147381450ab1d03e5fe939935354865f3e1f683. Main: 5b5afc2feeda2195f302380e615ba003d4906e09.
Pinned source blobs:
- research/wfp-ale/kernel-r19/kernel/src/redirect.rs 9a07e026134d46ef646d39862bd982cc48bbc5f6
- research/wfp-ale/kernel-r19/kernel/src/handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf
- research/wfp-ale/kernel-r19/kernel/src/lib.rs 0af6d4539673d2894cbaa91af0ea8f3524862a26

Source-verified sequence: a successful ioctl ARM sets configured and armed. Later ARM checks configured and rejects it. Process exit callback with null CreateInfo calls redirect::process_exit(pid). When broker pid matches, lose disarms and permanently kills Book; STOP and health loss do the same. Neither lose nor Book.kill clears configured. Pinned broker process pointer + pid guard all later IOCTLs. CLAIM also requires ready. There is NO supported same-driver re-ARM.

This narrows R44: its same-session Issue/Claim replay is a conditional future-receiver counterexample, not a demonstrated current-driver restart path. A new driver instance is NOT a re-ARM and is outside this research's permitted operations. Owner EXIT reporting latency, stale/buffered SSH data, external WFP policy, and OS egress are NOT proven safe.

Read-only checks: 11/11 Python unit tests pass; independent Node oracle enumerates 19,530 traces, of which 11,403 enter terminal loss and ZERO re-ARM violations; the weakened ARM EXIT ARM mutant breaks the invariant. 11/11 separate live GitHub blob-source assertions passed. Both are synthetic, with no driver, WFP, sockets, runner, Rust compiler or Windows native execution.

Decision: source-level one-shot gate holds if callback is delivered; restart recovery is a concrete design NO-GO. A new broker cannot merely repeat ARM. Do not reinterpret this as system-wide fail-closed proof.

Unresolved chain: PsSetCreateProcessNotifyRoutineEx exact process exit timing; PEPROCESS + creation epoch + start key + canonical EXE; ALE CONNECT_REDIRECT and AUTH_CONNECT V4/V6 issuance/re-auth; ALE_ORIGINAL_APP_ID; socket redirect records and SSH egress; sibling DIRECT, DNS/UDP, IPv4/IPv6 completeness, PID and tuple reuse, WFP loss and physical packets. No PacketBound/G2 or leak-free PASS.

Next authorized work: independent deterministic ordering model of broker EXIT, callback, Book.kill, in-flight CLAIM, established SSH relay. No kernel driver/callout/filter installation, driver signing, CI, VNC, networking configuration or paid action.

Official references:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
