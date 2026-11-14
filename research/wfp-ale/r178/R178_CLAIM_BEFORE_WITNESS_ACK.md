# R178 — CLAIM-before-Witness-ACK ordering counterexample

Independent FlowBridge WFP/ALE architecture research ONLY on research/windows-wfp-ale-attribution-20261107; 2026-11-14. NOT beta, PR #56, driver/packet acceptance, no-DIRECT or leak-free proof.

Source-pinned research parent: 8856f7536d0b9b0c5e561b7a0a98e6c3a3287f2a. Main (read-only): 5b5afc2feeda2195f302380e615ba003d4906e09.

Actual R19 Git blobs:
- kernel-r19/kernel/src/handoff.rs — e1d17217db50362ba9c4efc83af820b6beb094cf; Book::take checks auth_seen and FBR3 ticket, not a Witness ACK.
- kernel-r19/kernel/src/ledger.rs — b88c4c9237c4c118517978fc454f5048f522aa7f; separate 32-entry queue and destructive pop.
- kernel-r19/kernel/src/lib.rs — 53f5ce6faa0f9f591974287f38ea890cafeb0dd2; CLAIM and WITNESS IOCTLs are independent.
- kernel-r19/kernel/src/redirect.rs — a093f049d162987981a957aac90db1014bc6ff09; REDIRECT/AUTH and Book CLAIM have no Witness dependency.
- kernel-r19/broker_windows.rs — 329ef14b63e70226bfad7372b0014559213abd04; CLAIM before physical SSH setup; no Witness durable-ACK consumer.
Current R19 has NO active producer calling Ledger::observe. Any producer, atomically shared tx and ACK handshake in this experiment are **hypothetical** and NOT kernel proof.

## Negative result and proof scope

If the future implementation adds an authenticated Witness queue, durable journal and shared kernel transaction ID but still accepts CLAIM without journal ACK, the **audit-before-forward prefix** is not enforced. Model nine events, preserving two causal chains: R (issue) → P (redirect context published) → A (AUTH seen) → C (CLAIM) → S (first SSH byte), and R → Q (Witness enqueue) → L (lease) → J (durable journal) → K (ACK). Publication and queue are unordered unless an explicit atomicity rule is added.

After common R, the two ordered length-4 chains have C(8,4)=70 distinct interleavings per family label (IPv4/IPv6 labels do NOT model live IP packets). In the weak claim state: S<Q 1/70, S<J 15/70, S<K 35/70, C<K 55/70. Exact shortest queue gap: RPACSQLJK. Enqueue-before-publish Q<P leaves 35 schedules; ACK-before-CLAIM K<C leaves 15; both rules leave 10. These are **schedule counts not probabilities**.

Negative tests additionally exercise failed 33rd Witness enqueue after FBR3 publish, journal failure, and BFE/SSH revocation after ACK; all demonstrate why queue success, trusted durable ACK and live revocation each need independent checks. Proposed K<C prevents premature byte only under explicit model assumptions; it does NOT prove real disk fsync, a kernel transaction, native Windows classify, SSH forwarding, or system no-DIRECT.

## Reproduce

Run Python script in normal, -O and -OO, then --matrix > python.jsonl. Run node r178_independent_oracle.mjs > node.jsonl and compare the two files byte-for-byte. Executed locally: Python 8/8 tests in each mode; independent Node 140/140 rows identical, zero divergences. Matrix SHA-256 40688eba511b9414fcf62b2971b92557744cc617371e76ccbbfd86d43c8a8cd6. No rustc/cargo present; no Rust compile or native Windows/WFP test.

## Trust chain and architectural NO-GO

Kernel original process instance requires PsSetCreateProcessNotifyRoutineEx, referenced PEPROCESS/FileObject, PsGetProcessCreateTimeQuadPart, PsGetProcessStartKey, PID/creation epoch/canonical EXE; match true WFP ALE AppId/ORIGINAL_APP_ID and per-layer compartment for V4/V6, IPv6 scope and process/endpoint metadata. At CONNECT_REDIRECT pair FwpsQueryConnectionRedirectState0, FwpsAcquireWritableLayerDataPointer0, FWPS_CONNECT_REQUEST0.localRedirectContext/localRedirectTargetPID, FwpsApplyModifiedLayerData0 with subsequent AUTH_CONNECT and reauthorization proof. Atomic kernel transaction must bind FBR3 and a non-lossy Witness/tombstone, trusted broker verified via IoGetRequestorProcess, journaled/ACKed before CLAIM. On accepted socket WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT), then terminal CLAIM, then SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on physical SSH socket before TCP connect, host-key/user auth and SSH direct-tcpip, continual terminal revocation.

Original identity across kernel → redirect/auth → accepted socket → CLAIM → SSH is unproven. PID reuse, endpoint/5-tuple ABA, sibling DIRECT, DNS/UDP/QUIC, IPv4/v6 compartment/scope, reauthorization, process death and WFP/BFE/SSH loss stay NO-GO. No PacketBound/G2 PASS, no leak-free, no historical G1 transfer.

Microsoft primary docs:
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization

DECISION: NO-GO for merely adding producer+consumer+shared tx without ACK-gated CLAIM and atomic publication. Next decisive experiment: std-only Rust user-mode state-machine port and independent trace comparison on a Rust-enabled machine, then dual-origin and BFE-revocation race injections. No native driver/filter/host experiments until separate owner approval and rescue/rollback gates.
