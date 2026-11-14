# R183 — crash journal event order is not a recovery certificate

Date: 2026-11-14. Scope: only research/windows-wfp-ale-attribution-20261107 in i-shutov/flowbridge. Independent WFP/ALE R&D, not beta, PR #56, release, PacketBound/G2, no-DIRECT or leak-free certification.

## Pinned source and findings

Research HEAD before R183: 986db362a05ab57bc3f58d7f841be0be5a187451.
Main HEAD (read-only): 5b5afc2feeda2195f302380e615ba003d4906e09.

The exact R182 recovery source research/wfp-ale/r182/r182_crash_journal.py has Git blob f3af1252170595d4b7df00ee6ba5019b4f04c673. Its recover() function checks CRC32, length, transaction, session and membership in a SET of event names, but not their chronology. Consequently a complete journal in the order ACK → CLAIM → GRANT may pass the same-session strict predicate despite violating the intended durable GRANT → Witness ACK → CLAIM causal chain.

This is a defect in the **model-level recovery verifier**, not proof of a Windows driver defect. The prior R182 restart-with-NEW_SESSION fence still denies all old-session grants and is NOT invalidated by this finding. A producer that enforces event ordering before writing may be safe under additional independently established assumptions, but this recovery function does not attest those assumptions.

## Reproducible clean-room negative proof

The new Python program imports unmodified R182 encoded() and recover(). For each of the six permutations of GRANT, ACK and CLAIM for both v4 and v6 labels, it runs a REAL child process, writes all three CRC-framed records to a file, calls flush() and os.fsync() for each frame and terminates the child via os._exit(62). The parent compares the exact saved bytes with independently constructed expected frames, then invokes R182 recover(path, OLD_SESSION) and recover(path, NEW_SESSION).

Actual result: 12/12 child exits 62; 12/12 same-session legacy strict permits, of which 10 violate the causal order. A minimal strict ordered candidate accepts 2/12, one per family. NEW_SESSION rejects 12/12 old sessions. The independent Node.js oracle parses the SAME physical journal bytes (including fresh CRC32 implementation), verifies the event sequence and reproduces all 12 canonical rows exactly, with zero disagreements. Canonical SHA-256: 168554a0c64c09dcc921ab84b659a308867e149a09d78e2f39cccb5160fcbea1. These are deterministic user-mode program results, not measurements of Windows packets, WFP classify callbacks or SSH.

The previous R182 archive was also independently reproduced: all six checked Git blobs matched the R182 archive files, Python 7/7 normal, 7/7 -O, 7/7 -OO, Python/Node matrix 5760/5760 (SHA-256 8b50f19e50e0a5a24ce108d21ebbd979497f8524500496637ccc335a9a0e539a), and the seven real process-crash outputs matched SHA-256 42979e008548dc0ec1e7ead353fd7c23505de0061801fe14dfabf3c3bf7bdbf9.

Run from repository root with Python 3 and Node.js:

    python research/wfp-ale/r183/r183_order_probe.py self-test
    python research/wfp-ale/r183/r183_order_probe.py generate YOUR_WRITABLE_DIR > python.jsonl
    node research/wfp-ale/r183/r183_independent.mjs YOUR_WRITABLE_DIR > node.jsonl
    cmp python.jsonl node.jsonl

No Rust compiler is present in this executor; Rust compile/test pass is NOT claimed.

## Trust boundary and next decisive experiment

A future durable Witness protocol needs a typed, sequence-checked append-only state machine; the exact kernel-owned txid must bind a grant to its durable ACK and one-time CLAIM. Any missing/duplicate/conflicting/stale/out-of-order event must not increase authority. Durable state also requires a fresh native broker/BFE/SSH epoch fence; a CRC32-protected file is not cryptographic attestation.

Full native proof is still absent: PsSetCreateProcessNotifyRoutineEx + referenced PEPROCESS/file identity + PsGetProcessCreateTimeQuadPart/PsGetProcessStartKey for PID+creation epoch+canonical EXE; FwpmGetAppIdFromFileName0 and exact WFP AppId; ALE_CONNECT_REDIRECT_V4/V6 and FwpsQueryConnectionRedirectState0; ALE_AUTH_CONNECT_V4/V6 initial, UWP policy-honor, proxy and reauthorization (FWP_EMPTY and possible reverse packet direction); authenticated retained flow association only if FWPS_METADATA_FIELD_FLOW_HANDLE is genuinely delivered and FwpsFlowAssociateContext0 with flowDeleteFn is active; redirect CONTEXT/RECORDS queried with WSAIoctl on exact accepted socket; kernel Witness ACK, one-time DeviceIoControl CLAIM and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on physical SSH socket. A model-supplied native join is NOT evidence of an actual kernel join.

FwpmFilterEnum0 yields BFE management FILTER snapshots, not classifyFn's FWPS_INCOMING_METADATA_VALUES0; FwpmNetEventEnum5 returns historical event data with no attested Witness-to-socket transaction ID. A read-only user-mode inventory cannot by itself answer whether AUTH_CONNECT runtime metadata has exact flow continuity.

IPv4/IPv6 compartment scope, process death/PID reuse, reused five-tuple, sibling DIRECT, DNS/UDP/QUIC, WFP/BFE/SSH loss and physical no-DIRECT remain NO-GO. The next safe experiment is a real compiled std-only Rust user-mode typed-journal model on a separately available non-runner toolchain with independently verified negative traces. Native WFP/driver evidence requires a separate owner decision and all driver/VNC/SYSTEM rescue/rollback gates.

No main/release/beta/PR #56, runner/CI, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repos or automations changed. No kernel driver, callout, WFP filter, NDISRD, VNC, vendor binaries, ProxiFyre AGPL, PR40, C++ WFP payload, signed-driver work or paid operations.

Official contracts:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ns-fwpsu-fwps_incoming_metadata_values0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventenum5
