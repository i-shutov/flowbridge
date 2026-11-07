# R28 — endpoint tombstones narrow R27 ABA, but session rollover remains NO-GO

Date: 2026-11-08. Scope: **research/windows-wfp-ale-attribution-20261107 only**; independent clean-room offline architectural R&D. No driver/callout created, edited, compiled, loaded or installed. No WFP filter, service, runner, network configuration, security setting, other repo/ref, beta, PR #56, controller or automation mutated.

## Re-read source and authoritative limits

At the start of this cycle GitHub reported:
- Research HEAD: e8eac1ea1cb342b79fefdbb8bf21b57dec57397d (R27).
- main HEAD: 5b5afc2feeda2195f302380e615ba003d4906e09.
- Actual Rust handoff source: research/wfp-ale/kernel-r19/kernel/src/handoff.rs, Git blob f6200cac997f3c7e2fbd6a60443286727a8c2297.
- Redirect/auth callback source: research/wfp-ale/kernel-r19/kernel/src/redirect.rs, Git blob 6330935a8366d8ac573cbb2b474626f5883881f9.

The kernel Book issues a Context containing session bytes and an issuance sequence. **Book::attest receives Origin (PID, process creation epoch, start key, endpoint handle, owner generation) and Destination, not the Context session/sequence**. Book::issue prohibits a duplicate endpoint only while the previous slot is live, and it retires expired slots. Book::retire or a terminal Book::take also frees slots. An AUTH event bearing identical visible Origin/Destination after reuse therefore cannot be attributed to a particular issuance by this function alone.

This source finding does **not** establish an actual Windows event-delivery order, handle reuse or network leak.

## New negative scenarios and the bounded mitigation hypothesis

R27 checked expiry. R28 additionally checks two other retirement paths, conditional on a delayed/duplicate AUTH for the old ticket:
1. A retired using Book::retire, then B issued for same endpoint + same owner/destination.
2. A expired, then B issued (R27 replayed independently).
3. A successfully authorized and consumed via Book::take, then B issued, then an extra old AUTH(A) hypothetically arrives without the reauthorization flag.

In all three cases, AUTH(A) and AUTH(B) have identical inputs to Book::attest. An oracle that knows the issuance identity rejects AUTH(A) for B, while the current projection can mark B authorized. These are **conditional model histories**, not observed Windows traces; in particular a second non-reauthorization AUTH after a completed claim has not been shown physically possible.

A conservative *session-local endpoint tombstone* retains every endpoint handle ever issued until Book teardown. It rejects any attempted reissue, even after expiry, retire, CLAIM or ALE_ENDPOINT_CLOSURE. This prevents all three within-session ABA cases in the finite model, because B cannot exist for a previously used handle. Merely adding a timestamp, PID, canonical EXE, 5-tuple, or clearing a tombstone on endpoint closure does not provide an AUTH-visible issuance identifier.

**The price is severe:** with the existing fixed Book CAP=32 and a bounded non-evicting set of size 32, only 32 distinct endpoint handles could ever be issued in a session. Even after successful closure, a 33rd new endpoint would fail closed. This is a theoretical safety/liveness tradeoff, **not** a proposed kernel patch and **not** an architectural GO for product traffic.

**Cross-session NO-GO remains:** if Book/session is reset and an endpoint value is recycled, AUTH carries no Context session nonce or sequence in this implementation. Two separate sessions can again have equal AUTH inputs. This is conditionally ambiguous if Windows can deliver old indications across that boundary. The Microsoft documentation we checked does not supply the necessary total-order / global never-reuse guarantee. A proof would need such an OS contract or an actual issuance-bound native mechanism; a tombstone by itself is insufficient.

## Executed checks and source pin

Files published:
- r28_endpoint_tombstone_negative.py — clean-room projection, 6 Python 3.13 unittest methods PASS; 48 model worlds (2 IP families × 3 lifecycle paths × 8 identities), negative reused-endpoint and cross-session controls, normal first-use admission, terminal claim, wrong origin and CAP exhaustion.
- r28_independent_oracle.py — independent Book-free comparison of AUTH observations and true issuance labels: 48/48 observational-equivalence pairs; 4/4 flawed tombstone-erasure policies detected in selected histories.
- This report — evidence hierarchy and next experiment.

Exact Git blobs of both published Python files were compared with the **locally executed files** before making the commit. The tests do not import production Rust or the R27 Python projection and do not exercise the Windows kernel.

The optional --source argument to the test script rejects any local handoff.rs whose Git blob differs from the pinned SHA and checks source decision snippets. **That optional source-pin invocation was not performed** because the exact checkout is not mounted in the local Python environment. Instead, the exact original Rust blob and function bodies were independently read through the GitHub connection. No rustc/cargo was available. No driver or CI/runner was used.

## Windows API evidence hierarchy

1. **Owner identity**: PsSetCreateProcessNotifyRoutineEx with PS_CREATE_NOTIFY_INFO.ImageFileName and FileObject; PsGetProcessCreateTimeQuadPart, PsGetProcessStartKey and referenced kernel objects. These pin a process generation but not a per-connection issuance in isolation.
2. **Native redirect**: FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 with FWPS_METADATA_FIELD_PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE, FWPS_CONNECT_REQUEST0.localRedirectContext, localRedirectTargetPID and a handle created by FwpsRedirectHandleCreate0. Use FwpsQueryConnectionRedirectState0 for redirect-loop handling. The R26 source emits a 128-byte private Context.
3. **Native AUTH_CONNECT**: FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6; redirected condition flag, ALE_ORIGINAL_APP_ID, metadata ORIGINAL_DESTINATION, LOCAL_REDIRECT_TARGET_PID, PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE, process epoch/start key. All are necessary observations; those inspected R26 fields are not the private ticket issuance sequence.
4. **Accepted socket / outbound tracking**: WSAIoctl with SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT on the accepted socket, terminal kernel CLAIM, and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on the outbound socket before connect. User-mode tuple/PID joins cannot replace a native AUTH receipt.
5. **Physical proof**: independent filter arbitration and egress observation across IPv4/IPv6, sibling DIRECT, DNS/UDP/QUIC and loss of WFP/BFE/SSH, plus process-death/PID-reuse and re-used 5-tuple tests. No such native evidence was collected this cycle.

Microsoft [ALE Endpoint Lifetime Management](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management) documents a unique endpoint handle for each endpoint and that TCP endpoint closure is indicated for each AUTH_CONNECT; it **does not explicitly document** a globally monotonic handle ID or a total order excluding the hypothetical delayed AUTH after handle reuse. [FwpsQueryConnectionRedirectState0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0) says its redirect-records handle is supplied at ALE_CONNECT_REDIRECT; it is not evidence that the same context is accessible at AUTH. [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection) documents redirect records/context in the accepted proxy socket and forwarding records to the outbound socket. [WFP metadata identifiers](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers) lists endpoint, process, original destination and redirect PID metadata, not an issuance nonce.

## Decision and next experiment

**Conditional model GO** for per-session non-reissuance as a narrow ABA prevention invariant; **NO-GO** for cross-session issuance proof, native AUTH provenance, PacketBound/G2, system no-DIRECT/leak-free and fail-closed. No transfer of historical G1 acceptance (dd1ab3c).

Next permitted: execute the exact source-pin test in an allowed local checkout and review Microsoft endpoint-handle/closure/reauthorization ordering for a definitive no-reuse guarantee or documented AUTH-visible redirect context. If neither is established, STOP at conditional NO-GO. Native driver execution, signature, VNC/SYSTEM rescue, rollback and physical leak testing would require separate owner approval and gates and are not authorized by this research task.
