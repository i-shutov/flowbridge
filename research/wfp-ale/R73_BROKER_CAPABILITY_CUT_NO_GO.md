# R73 — accepted-socket/broker capability boundary (architectural NO-GO)

Date: 2026-11-09. Research-only branch research/windows-wfp-ale-attribution-20261107. Research baseline e29b1eddaa82c2193b541a5772d2e115c9e92792; main 5b5afc2feeda2195f302380e615ba003d4906e09. No driver, filters, Windows experiments or CI.

## New concrete finding (independent source audit: 8/8)

Source blob broker_windows.rs 16ec8853d322b40f0e00e14d49ae3410741b9395: private Received fields bind accepted TcpStream, redirect context and records in receive(accepted), queried by WSAIoctl on the same socket. But Device::command is PUBLIC and allows an arbitrary CLAIM byte slice. The normal Received::claim_and_connect_trusted_ssh path calls it; other safe-Rust code in this process can also call the raw method without an accepted socket. Private Received is NOT an exclusive CLAIM capability.

Kernel lib.rs blob 0af6d4539673d2894cbaa91af0ea8f3524862a26 sends redirect::ioctl(code,input,IoGetRequestorProcess(irp)); redirect.rs blob 9a07e026134d46ef646d39862bd982cc48bbc5f6 and handoff.rs blob e1d17217db50362ba9c4efc83af820b6beb094cf check the broker, one-shot AUTH receipt, original process identity, endpoint and ticket, but pass no accepted-socket witness into Book::take. A valid ticket A can therefore be CLAIMed by the same authenticated broker while it is handling accepted socket B. This is a **protocol capability distinction**, not evidence that the unmodified broker swaps sockets or an external unprivileged attack.

## Platform API boundary

- WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT / RECORDS) is socket-specific, but returns data to the caller; later DeviceIoControl(CLAIM, bytes) does not prove the socket association.
  https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
  https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- WSADuplicateSocket returns protocol info for sharing the socket; it is not an ALE original-owner attestation:
  https://learn.microsoft.com/en-us/windows/desktop/api/winsock2/nf-winsock2-wsaduplicatesocketa
- ObReferenceObjectByHandle validates and references an object, but no documented mapping was established between a user-provided accepted Winsock handle and the redirect context of this ticket; user handles require UserMode access validation:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle
- WSK is a separate kernel socket interface; WskControlSocket documentation does not establish an automatic Winsock SOCKET to WSK_SOCKET conversion:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-winsock-kernel
- FwpsFlowAssociateContext0 uses flow IDs from WFP metadata, not a socket/CLAIM certificate:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0

## Executable negative test and independent oracle

Python r73_broker_cut.py: 12/12 unittest PASS. Node r73_independent_oracle.mjs: independently written bitmask oracle. Both enumerate 11 Boolean input facts for each of IPv4/IPv6, 4096 synthetic worlds, and agree on ordered SHA256
afa2ba3288c5c4a8558236f614805832a915bf75d7a73d9c7bd56b5a9077f7b7.
Model counts: kernel candidate 256; typed trusted-broker candidate 8; hypothetical physical candidate 2; 128 kernel candidates lack socket pairing; 128 have raw-command bypass. Overlap exists. No observed packet counts, no Windows runtime and no proof that physical states occur. The model's hypothetical physical flags are assumed inputs.

**Conditional GO:** the fully trusted unchanged broker can preserve accepted-socket/WFP context pairing in its Received type. **NO-GO:** kernel-independent accepted-socket proof through the existing CLAIM protocol, or physical leak-free/no-DIRECT claims.

R74 decisive next experiment: deterministic source-derived teardown/fault injection for terminal Book::take and failed SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, failed SSH authentication, process death/PID reuse, re-used 5-tuple, v4/v6, WFP/SSH loss; require no ticket reuse and no silent DIRECT. Later consider privately scoping Device::command and a typed CLAIM method as user-mode TCB hardening only, not as kernel proof.

Unproven and unchanged: sibling DIRECT suppression, DNS/UDP/QUIC, WFP-loss behavior, packet-bound G2, historic G1 dd1ab3c. main, release, beta integration/windows-rust-capture-agent-20261031, PR #56, runner, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, services, network, other repos and automation untouched.
