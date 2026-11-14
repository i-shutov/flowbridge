# R177 — Crash-window lease/ACK state-machine negative tests

Date: 2026-11-14. Track ONLY research/windows-wfp-ale-attribution-20261107; no beta/PR #56, native driver, WFP filter, network, security-setting, runner or automation modification.

## Fixed source boundary

Research base HEAD: 300ef4ee7281aa9c73e9a009c2cdcb9585a46b94.
Read-only main HEAD: 5b5afc2feeda2195f302380e615ba003d4906e09.

R19 source blobs read at research HEAD:
- kernel-r19/kernel/src/ledger.rs — b88c4c9237c4c118517978fc454f5048f522aa7f; pop destructively removes without ACK
- kernel-r19/kernel/src/lib.rs — 53f5ce6faa0f9f591974287f38ea890cafeb0dd2; WITNESS IOCTL delivers without consumer confirmation
- kernel-r19/kernel/src/handoff.rs — e1d17217db50362ba9c4efc83af820b6beb094cf; FBR3 Book session/sequence differ from Ledger
- kernel-r19/kernel/src/redirect.rs — a093f049d162987981a957aac90db1014bc6ff09; broker process exit and lease loss trigger terminal Book kill
- kernel-r19/broker_windows.rs — 329ef14b63e70226bfad7372b0014559213abd04; no active Witness reader/ACK
- kernel-r19/kernel/wrapper.h — 3fc86a6cc03528c1384954490b796bd97f34338c; METHOD_BUFFERED, FILE_READ_DATA

The proposed PEEK/LEASE -> journal -> ACK protocol is NOT implemented by R19 and NOT an authenticated native kernel witness. R165/172/173/174/175/176 remain blockers.

## Experiment, executed offline

Run from this directory:

    python3 r177_lease_ack_negative.py
    python3 -O r177_lease_ack_negative.py
    python3 -OO r177_lease_ack_negative.py
    python3 r177_lease_ack_negative.py --matrix > python.jsonl
    node r177_independent.mjs > node.jsonl
    cmp python.jsonl node.jsonl
    sha256sum python.jsonl

Python: 8/8 tests in EACH of the three modes. Independent Node.js formula oracle: 160/160 matrix rows byte identical, zero disagreements; plus 7 token-invalidity checks. SHA256 of the canonical matrix: c883ef3a79e7c487659cbd371f0054e136e335e9a2446282efbbfeddd3b22947.

The matrix exhausts one worker crash position, IPv4 and IPv6 labels, 1-4 records and two worker orderings:
- Proposed persist-before-ACK: all 80/80 schedules recover with no missing receipts (MODEL-ONLY conditional GO given durable, idempotent journal and a still-living broker/kernel).
- ACK-before-persist negative mutant: 20/80 schedules lose exactly one receipt despite final EMPTY and lost=false. 8/20 miss the tail, hiding any later sequence gap. Protocol-level NO-GO.
- Separate negative tests: only exact session+broker process creation epoch+canonical executable+receipt+transaction+lease generation+deadline can ACK; 32/33 overflow sticky; process death tombstone preserves receipt and invalidates old lease; stale ACK, PID reuse, endpoint/tx reuse, competing reader and terminal SSH/BFE/broker loss rejected.

Important assumptions: the simulated journal is an in-memory set standing for DURABLE fsync. It does NOT prove actual disk persistence, Windows kernel code, native ALE, file-object lifetime, network enforcement, SSH exactly-once forwarding or recovery from OS reboot. A model of terminal broker death fails closed and does not recover. Source-gated native WFP proof is absent. rustc/cargo unavailable in this runtime; these are genuinely executed Python and independent Node tests, NOT compiled Rust.

## Minimal design boundary

1. A single kernel-owned transaction ID must be present in both FBR3 and Witness, bound atomically to referenced original process/image identity, PID+creation epoch+start key, native AppId, endpoint and generation, IP family, original address/port, compartment and IPv6 scope. Synthetic client IDs, PID/tuple correlations and WFP redirect records alone are not proof.
2. Exclusive broker PEEK/LEASE authenticates the OS requestor process instance (IoGetRequestorProcess, referenced process, epoch, image) and returns an immutable typed evidence-or-tombstone record with receipt, transaction, session, lease generation and deadline. Other administrators/readers must not steal the queue.
3. An idempotent persisted journal of (session, receipt, tx, kind) is committed and fsync-verified BEFORE ACK; failure to persist means no ACK. ACK atomically removes only the matching head; duplicate and stale tokens fail. Worker crash after persist before ACK may redeliver but cannot silently lose a receipt. This does not imply kernel can prove disk fsync.
4. Broker process death, owner death where unsafe, BFE/SSH loss, ambiguity, queue overflow, reused endpoint/transaction and reauthorization must fail closed; a terminal Book kill by itself is not proof of an OS-wide DIRECT block.
5. The state machine concerns delivery only. The real native boundary still requires PsSetCreateProcessNotifyRoutineEx, PsGetProcessCreateTimeQuadPart, PsGetProcessStartKey, FwpmGetAppIdFromFileName0, FWPS ALE_CONNECT_REDIRECT/AUTH_CONNECT V4/V6, FwpsQueryConnectionRedirectState0, FwpsAcquireWritableLayerDataPointer0, FWPS_CONNECT_REQUEST0.localRedirectContext/localRedirectTargetPID, FwpsApplyModifiedLayerData0, accepted-socket WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT), one-time DeviceIoControl(CLAIM), physical SSH socket WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS), and independent WFP/BFE admission evidence.
6. PID reuse, reused 5-tuple, sibling DIRECT, DNS/UDP/QUIC, compartments, IPv6 link-local/scope, reauthorization and WFP/SSH failure remain architecture NO-GO. No PacketBound/G2 PASS, no-DIRECT, leak-free or historical G1 transfer.

Official docs:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogetrequestorprocess

NEXT: std-only, source-pinned Rust user-mode port with runnable exhaustive fault injection on a Rust-enabled test host, independent trace comparison to these Python/Node oracles. No driver/filter/host experiments without separate owner decision and all rescue/rollback gates.
