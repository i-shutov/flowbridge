# R176 — Successful Witness POP lacks a delivery ACK

2026-11-14. Independent WFP/ALE architecture research only; not beta, PR #56, or G2 acceptance.

## Source-pinned conditional NO-GO

Research base HEAD: 7927e93360021adce1e6d609b77f470097da4938. Read-only main HEAD: 5b5afc2feeda2195f302380e615ba003d4906e09.

Exact R19 Git blobs under research/wfp-ale/kernel-r19/:
- kernel/src/ledger.rs: b88c4c9237c4c118517978fc454f5048f522aa7f
- kernel/src/lib.rs: 53f5ce6faa0f9f591974287f38ea890cafeb0dd2
- broker_windows.rs: 329ef14b63e70226bfad7372b0014559213abd04
- kernel/src/redirect.rs: a093f049d162987981a957aac90db1014bc6ff09

Ledger::pop advances the queue and clears the receipt before successful IOCTL completion. It has no ACK operation; lib.rs::dispatch reports SUCCESS after copying the Witness without knowing if its consumer durably processed it. EMPTY carries no receipt high-water mark. An independent read worker losing volatile state after a successful pop can lose a live-owner Witness without changing Ledger.lost. A future receipt may expose the gap, but a trailing lost receipt cannot be identified from EMPTY alone. R175's dead-owner failed-read path is different.

Critical mitigation: real broker *process* termination invokes redirect::process_exit -> lose() -> Book::kill(), so process death is terminal/fail-closed in R19. Here the offline countermodel assumes reader/worker failure while the broker process stays alive. R165 and R173 already establish that current R19 lacks both a runtime producer and a broker consumer, so this is a future integration gate, not a demonstrated network leak.

## Executed independent negative tests

Run: python3 r176_pop_crash.py ; python3 -O r176_pop_crash.py ; python3 -OO r176_pop_crash.py
Then: python3 r176_pop_crash.py --matrix > python.jsonl ; node r176_independent.mjs > node.jsonl ; cmp python.jsonl node.jsonl

Results: Python 9/9 under all 3 modes; independent Node.js algebraic oracle 110/110 byte-identical rows; 0 divergence. Model labels both IPv4/IPv6 and exhausts 1–5 live-owner receipts with every read/persist crash window. 70/110 rows lose receipts, 30/110 lose a trailing receipt; all 110 report EMPTY and lost=false. Boundary: 32 successful pops can all disappear in this model without sticky loss; 33 unread observations latch lost=true. JSONL SHA256: df2cee370c44d5765bc1b2f1db4544b46c2ddc7e23e4cabefcb58aae22963a99.

This is an offline source-semantic projection, *not* a native Rust, Windows, driver, WFP, or network proof. No local full source checkout; source files were inspected by exact GitHub blobs.

## Architecture experiment next

Before wiring R165 producer, R172 authorized reader, R173 backpressure, R174 shared FBR3 identity and R175 typed dead-owner tombstones, prototype a session-bound exclusive PEEK/LEASE -> durable receipt/tombstone -> ACK protocol. Test crash after PEEK and after durable persistence before ACK; stale ACKs, PID/endpoint ABA, 32/33 overflow, reauthorization and BFE/SSH loss. ACK must never be interpreted as ALE provenance. A clean-room std-only Rust model with independent oracle is next; rustc/cargo unavailable here. Native classify work requires separate owner gates.

Kernel trust still needs referenced PEPROCESS/FileObject + PID/creation epoch/start key/canonical EXE, WFP AppId, ALE_CONNECT_REDIRECT/AUTH_CONNECT V4/V6, compartment/scope/endpoint identity, FwpsQueryConnectionRedirectState0, accepted-socket WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS, one-shot CLAIM and physical SSH socket SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS. Sibling DIRECT, DNS/UDP/QUIC, PID/5-tuple reuse and WFP/BFE/SSH failure remain NO-GO. No PacketBound/G2 PASS, no-DIRECT or leak-free assertion.

Official documentation: https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

No protected branches, beta, PR #56, driver/filter/runner/service/network/security/automation/other-repo changes.
