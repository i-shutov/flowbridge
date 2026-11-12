# R131 — dynamic-session protection lifetime: source-bound negative proof

2026-11-12. Research only, not beta, release, PR #56 or G2.
Source at research HEAD 0f1bd42e2639aae456b549c3e67697b7f52572e9:
- `research/wfp-ale/kernel-r19/policy_windows.rs` blob `acf60334320d970f58af3349ee75fbaa59826602`.
- `Engine::open()` sets `FWPM_SESSION_FLAG_DYNAMIC`.
- `Engine::close()` and `Drop for Engine` call `FwpmEngineClose0`; `Installed` owns the engine.
- `RULES` in `policy_plan.rs` are exactly two AUTH_CONNECT and two CONNECT_REDIRECT filters.
- No independent FlowBridge-owned persistent/boot rule is installed by this policy code.

Official Microsoft contract: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
and https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
WFP dynamic-session objects are automatically deleted when their session ends, including closure on client exit / RPC rundown.

Counterexample at **policy-coverage level**, not a packet observation:
t0: four dynamic FlowBridge filters installed during live session.
t1: owning management process/session exits while selected application remains.
t2: BFE destroys owning session and its four dynamic filters.
t3: selected process initiates a new TCP connection. No FlowBridge-owned filter remains to invoke the R19 classify function. Actual network result depends on other policies and is **NOT MEASURED**.

The kernel book and broker SSH health alone cannot preserve classification coverage when the matching policy objects have disappeared. Reopening an engine does not reconstitute deleted rules; a new commit and exact readback are necessary, with a protection gap to account for.

A fail-closed production design needs an **independently admitted enforcement layer** whose lifetime does not share this dynamic owner session, plus atomic startup/shutdown/loss recovery guarantees. This does not authorize persistent/boot policy installation or any driver experiments.

Verification: 256 deterministic synthetic cases; Python unittest 6/6; independent Node oracle 256/256; matrix SHA256 b6a27a2cddf7066c2233181ab719db47a22e5be51d8f63f87aaf04a18716a515. 32 states have FlowBridge-owned rules present, 224 lack them, including all closed/rundown/owner-exit states. Model contains no Windows API or packets. It **does not** assert actual DIRECT success or leak-free behavior.

Next decisive permitted step: execute R130 exact-source user-mode Rust tests on the approved native Windows host, obtain complete evidence and SHA. WFP physical admission still requires separate owner decision and rescue/rollback gates.