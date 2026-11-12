# R136 bounded independent review tasks — NOT DISPATCHED

No actual model-subagent/Windows executor is claimed. These are scoped tasks for
small independent reviewers only, without authorization to run or mutate any
kernel, network/security/policy settings, service, CI or repository branch.

1. Windows FFI reviewer: verify `GetModuleHandleW(NULL)` borrowed module-base,
   `K32GetMappedFileNameW` export on Windows 10, `VirtualQuery` x64 ABI/type,
   `FILE_ID_INFO` 24-byte field layout, all ownership/free/error cases and
   `GetFinalPathNameByHandleW` NT path. Produce concrete line comments and tests,
   not a blanket PASS. No remote host access.
2. Oracle reviewer: derive the 7 required predicates without reading
   `r136_oracle.py`, challenge JSON spoofing of addresses, raw masks, booleans,
   nonempty identifiers and repeated AppId. The optional module filename bit must
   not become security evidence. Provide one failed mutation and corrected oracle.
3. Windows operator, owner-approved **user-mode read-only** only: run the pinned
   script with `-RunSelfMappedImage`, upload `evidence-only.zip`, preserve errors;
   do not install new toolchain/driver/filter, change ACLs or network settings.

Separate kernel/VNC/SYSTEM rescue/signed driver approval still required for
actual ALE classify experiments; nothing in R136 lifts that gate.
