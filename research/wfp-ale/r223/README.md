# R223 — a fresh CLAIM alone cannot repair stale PING renewal

2026-11-24. Only research/windows-wfp-ale-attribution-20261107, parent 6cfa2cb3da99fa178d308ff14721ae9a9cc34ef6; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. No beta, PR #56, kernel/driver or physical packet evidence.

## New composition counterexample to a partial R222 repair

R222 established pre-lock CLAIM freshness. This cycle checks the distinct consequence of a pre-lock PING sample used both for the lease predicate and the renewal write. Pinned R19 redirect.rs blob a093f049d162987981a957aac90db1014bc6ff09: lines 12–15 make observed lease loss terminal, line 28 samples before Guard::take, line 41 checks ready(time) then writes last=time, lines 43–45 check ready and take. handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf lines 10–11, 113–117: LEASE=3s, TTL=10s, inclusive deadline, one-use AUTH-attested ticket. lib.rs 53f5ce6faa0f9f591974287f38ea890cafeb0dd2 lines 44,69,136: spinlock, process death, IOCTL dispatch. Broker shares one synchronous Device (broker.rs 6163e84aea08ddde7e51a7fb94ccb6d68ae951fb; broker_windows.rs 329ef14b63e70226bfad7372b0014559213abd04).

Let H be the previous last heartbeat, D=H+LEASE. A PING samples S=D-1ms but acquires the lock at C=D+1ms. No other gate has observed expiry or latched terminal loss. With the existing adapter ready(S) succeeds and last=S is written. A subsequent fully fresh CLAIM at Q=D+2ms passes the renewed lease; a previously AUTH-attested ticket issued roughly H is still younger than TTL. Under a strict lease-at-locked-renewal contract PING must instead fail at C, latch loss and deny the subsequent CLAIM. No overlap of PING and CLAIM IOCTLs is needed. No already-latched loss is reversed. This is a conditional temporal counterexample, not measured Windows scheduling, a kernel identity bypass, or a physical traffic leak. If the intended contract is request-entry time rather than locked renewal time, the discrepancy is a specification choice, not a proven violation.

Repairing only CLAIM's timestamp is therefore insufficient for strict locked-renewal semantics. Both PING and CLAIM must use a consistent locked-time sample; ARM and AUTH timing must be separately specified (AUTH currently calls now twice). Even this correction cannot make a later WFP arbitration or physical SSH action atomic with the lease.

Microsoft documents KeQueryInterruptTimePrecise at any IRQL, with 100ns units and microsecond accuracy: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttimeprecise . No native timing proof. See also https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquirespinlockraisetodpc and https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol .

## Executed negative tests

Python absolute-time sticky state machine and independently implemented Node age-domain algebra: 800 synthetic rows each, 98 counterexamples where fixing CLAIM alone still admits after late PING renewal. Both oracles check ten explicit witnesses (including 1ms margin on either side of expiry), boundary acceptance, expiry denial, and mutation distinguishing fixing PING from fixing CLAIM. IPv4/IPv6 are labels only. Output digest d537bf2c97bf4943bf0fadf599ea577f3a2b7662782ded86002ce03adb76c087. Python blob 2327154374898a5f3cddb3120dd25875fe01493a; JS blob 0481251c50f694793377b5ac16e161edd01a5db3. node --check PASS.

    python3 negative.py
    node --check independent.mjs
    node independent.mjs

All non-temporal guards assumed valid, previously issued and attested ticket, no intervening loss, no PING/CLAIM overlap. The old CLAIM sample is simplified to the PING-return instant C; the decisive comparison uses the fresh CLAIM time Q. Results are model cases, not probabilities or native measurements. Rust compiler unavailable, no Rust execution.

## Boundary and next decisive step

PsSetCreateProcessNotifyRoutineEx referenced EPROCESS/FileObject, PID + epoch (PsGetProcessCreateTimeQuadPart) + start key (PsGetProcessStartKey) + canonical EXE/AppId (FwpmGetAppIdFromFileName0) -> native ALE CONNECT_REDIRECT/AUTH_CONNECT V4/V6 and final arbitration -> accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS -> terminal CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before physical authenticated SSH. R201, R202, R218, R220, R221 limitations remain: process death/PID reuse, reused 5-tuple, sibling DIRECT, mapped IPv6, DNS/UDP/QUIC and WFP/BFE/SSH loss lack native proof. No G2/PacketBound, no-DIRECT/leak-free or historic G1 transfer.

Next: compile exact pure Rust models R201/R202/R218–R221 and a value-only time-transition contract in an admitted offline toolchain. Native experiments require independent owner and rescue/rollback gates. No driver, callout, WFP filters, network/runner/system changes, protected branches or automation changes. No paid operations.
