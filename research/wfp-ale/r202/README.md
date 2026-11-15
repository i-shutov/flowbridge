# R202 — Dynamic BFE policy ownership NO-GO

Research parent: e2598ba1289c2e9a53bbe49cdee34f4a1976f7a5. Research branch only, not beta, PR #56, driver QA or G2.

R19 policy_windows.rs opens FwpmEngineOpen0 with FWPM_SESSION_FLAG_DYNAMIC. Installed owns this engine; policy_plan::install adds four selected-app TCP filters with FwpmFilterAdd0: CONNECT_REDIRECT/AUTH_CONNECT v4/v6. Filter flags are zero. Kernel FwpsCalloutRegister1 registration is separate and does not itself guarantee active classification.

Microsoft explicitly documents that dynamic-session WFP objects are removed when the session terminates, including termination of the process owning the session. Therefore after such teardown the four R19-owned filters are unavailable to invoke the kernel callouts. This is an architectural NO-GO for guarantee of continuous FlowBridge-owned filtering after session-owner loss. It is NOT a measured DIRECT connection, evidence about foreign filters, measured teardown latency, or a claim that the SSH broker necessarily owns this session.

Pinned source blobs: policy_windows.rs acf60334320d970f58af3349ee75fbaa59826602; policy_plan.rs 0c3d0e88eb9d06f4030131d9533da2d629dbdab0; kernel/src/lib.rs 53f5ce6faa0f9f591974287f38ea890cafeb0dd2; kernel/src/redirect.rs a093f049d162987981a957aac90db1014bc6ff09.

Microsoft documentation: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0 and https://learn.microsoft.com/en-us/windows/win32/fwp/object-management and https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0 .

Independent Python negative oracle: 7/7 executed PASS. Independent JavaScript source predicates: 12/12 executed PASS against the pinned blobs, including mutation sensitivity. Pure std-only Rust test model: 8 tests written but uncompiled because rustc unavailable. None is Windows/BFE runtime or native WFP proof.

Next permitted work: compile R201/R202 offline Rust tests; build R199 read-only on an approved Windows 10 Pro x64 host and record exact OS/rustc, binary hash, BFE API return codes and ACL. Positive-to-negative active BFE lifecycle requires separately approved filter/driver/VNC/SYSTEM and rescue/rollback gates: do not run under this gate. Kernel-origin identity, PID/epoch/canonical EXE, ALE v4/v6, accepted-socket WFP records, terminal CLAIM, SSH, PID/5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, and loss remain without native proof.