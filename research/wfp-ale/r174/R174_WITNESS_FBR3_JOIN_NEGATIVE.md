# R174 — Witness/FBR3 join is not a proof of ticket identity

Date: 2026-11-14. Independent WFP/ALE R&D ONLY; not beta, PR #56 or PacketBound/G2 acceptance.

## Exact source anchors

Research parent HEAD `1445a4fd6f280ed0d056867fb8188f6438af96a5`; read-only main `5b5afc2feeda2195f302380e615ba003d4906e09`.

- `kernel/src/ledger.rs` Git blob `b88c4c9237c4c118517978fc454f5048f522aa7f`: Witness has its own u64 session and receipt, endpoint, pid, epoch, process start key, owner generation, family, protocol, flags, AppId. It lacks FBR3 session, Book sequence, original destination and timestamp.
- `kernel/src/handoff.rs` blob `e1d17217db50362ba9c4efc83af820b6beb094cf`: FBR3 Context uses an independent 16-byte Book session and its own sequence; it carries original IP/port and issued_at but no Ledger receipt or Ledger session.
- `kernel/src/redirect.rs` blob `a093f049d162987981a957aac90db1014bc6ff09`: Book session comes from BCryptGenRandom; Book issues at REDIRECT, attests at AUTH.
- `kernel/src/lib.rs` blob `53f5ce6faa0f9f591974287f38ea890cafeb0dd2`: Ledger session is derived from KeQueryPerformanceCounter; R19 has no runtime Ledger::observe producer.

### Conditional protocol NO-GO

Merely connecting the Witness producer and broker consumer does **not** provide a kernel-verifiable one-to-one join between Witness and the *same FBR3 ticket*. PID/epoch/start key/endpoint/family agree in projections, but these are correlation fields, not a shared ticket identifier. Distinct counterfactual valid histories produce the same modeled Witness and different FBR3 sequence/destination/session/timestamp. The R19 producer is not live; this is NOT a live Windows collision, successful privilege attack or DIRECT leak. R165/R172/R173 remain independent unresolved prerequisites.

### Offline negative tests

Run `python3 r174_projection.py`, `python3 -O r174_projection.py`, `python3 -OO r174_projection.py`, then compare `python3 r174_projection.py --matrix` with `node r174_independent.mjs` as byte-identical JSONL. The semantic projections cover 90 rows, both IP families, distinct destinations, ports, Book sequences, Book sessions and issue times. A separate negative test models an unrelated ticket for a different endpoint followed by retirement: Book sequence advances while Ledger receipt remains 1, respecting endpoint tombstones. Matrix SHA256: `a2f8c0a780491b186c8ca4252f4beb2e78855ad4c22089a8477a9f82437059f6`. Python 6/6 normal/-O/-OO; Node 90/90; divergence 0. These are independent deterministic models, NOT Rust compilation, native WFP testing or kernel proof.

### Decisive experiment / trust boundary

Specify an atomic kernel-issued transaction identity (not a join by PID/5-tuple), bind exact original AppId plus PID/creation epoch/start key and referenced process/image, original destination, endpoint, compartment and IPv6 scope to REDIRECT and AUTH; carry it unchanged through accepted-socket `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT`, terminal CLAIM and `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the physical SSH socket. Define reader authority, ordering, acks and queue-loss behavior before enabling producer. Explicitly test process death/PID reuse, endpoint ABA, sibling DIRECT, UDP/DNS, reauthorization, BFE/SSH failure. Native proof remains prohibited without separate owner permission and all driver/VNC/SYSTEM rescue/rollback gates. No changes to main/release, beta, PR #56, services, networking, firewall, Windows security, runners, automations or other repos.

Official API: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking ; https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context ; https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records .

No local full-checkout source gate and no Rust compiler; exact Git blobs verified via the GitHub connector.