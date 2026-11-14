# R192 — CONNECT_REDIRECT AppId/ARM mismatch skips the fail-closed readiness gate

Date: 2026-11-14. **Only** i-shutov/flowbridge branch research/windows-wfp-ale-attribution-20261107, parent 4727ab81f313d0d478c2d4ac860e24b153b5259a. main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. Independent architecture R&D; NOT beta, PR #56, release, PacketBound/G2, leak-free or native Windows admission.

## Source-grounded finding

The R19 BFE policy is separately scoped by \`FWPM_CONDITION_ALE_APP_ID\` to the selected EXE. The ARM IOCTL independently supplies a target AppId/name. The ARM path verifies it differs from the broker executable, but does **not** compare it against the actually installed BFE filter's AppId bytes. A policy for selected EXE **A** can therefore be structurally present while the route is configured with name **B**, given an incorrect/out-of-sync management plan. No claim is made that the current production controller normally creates that mismatch.

The original kernel callout adapter in \`kernel-r19/kernel/src/lib.rs\` sets \`FWP_ACTION_CONTINUE\` whenever \`FWPS_RIGHT_ACTION_WRITE\` is present, **before** dispatching to \`redirect::classify\`. The latter checks \`configured\` early and blocks if false, but after reading the WFP AppId has the exact early return \`if appid!=&r.name[..r.len]{return;}\`. This return occurs **before** \`ready(time)\`, endpoint/process/lifetime checks, lease expiry or the one-use ticket. Consequently, with a live matching BFE filter, a configured route name mismatch and action-write right, R19's registered callback returns **CONTINUE** without a FlowBridge block/redirect, even when \`armed=false\` (e.g., after STOP). These are real **source-code control-flow facts**, not observations of packet egress. Other WFP policy may block, and the final outcome is unknown.

The correct contrast: when BFE-selected AppId and armed route name agree, then (given valid metadata/inputs) \`ready(time)\` can reject an unarmed/expired/lost session. The mismatch bypasses this security gate entirely. The no-write-right case is expressly UNKNOWN/PRESERVED; the caller must not assume it becomes a permitted flow.

## Independent reproducible negative tests

- \`python3 research/wfp-ale/r192/route_appid_negative.py\` (normal, \`-O\`, \`-OO\`): **7/7** each.
- \`python3 research/wfp-ale/r192/route_appid_negative.py --matrix\` against \`node research/wfp-ale/r192/independent_oracle.mjs\`: **512/512 identical ordered CSV cases**, SHA-256 \`14723c73028561d664fcfa064b759e4b5d0cf2842bdec1c71aae88066d131bdd\`.
- 16/512 synthetic cases show \`CONTINUE_NO_READY_CHECK\` (v4/v6, armed/unarmed, simulated process live/dead and SSH alive/dead), subject to explicitly active selected BFE filter, configured mismatched route and writable classify action.
- Other cases are conservatively \`NO_FILTER_UNKNOWN\`, \`OUT_OF_SCOPE\`, \`PRIOR_ACTION_UNKNOWN\`, \`BLOCK_BEFORE_APPID\`, \`BLOCK_AFTER_READY_CHECK\` (valid-input model) or \`REQUIRES_NATIVE_PROOF\`. The two last axes, process/SSH liveness, are *not* WFP measurements; they illustrate that the early return precedes those gates, not actual process or SSH behavior.
- The optional \`--source <repository-root>\` assertion checks the three **actual** R19 source paths and ordering. Source guard was independently matched against fetched current GitHub blobs before publication; on the offline test host those full R19 paths were not available, so the source-guard CLI was not run there. No Rust or native Windows compilation was performed.
- Pinned Git blob identities: \`lib.rs\` 53f5ce6faa0f9f591974287f38ea890cafeb0dd2, \`redirect.rs\` a093f049d162987981a957aac90db1014bc6ff09, \`policy_windows.rs\` acf60334320d970f58af3349ee75fbaa59826602.

## Documentation and trust boundary

Microsoft documentation: [Deep Inspection / classifyOut action](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-a-callout-for-deep-inspection), [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection), [Using Proxied Connections Tracking](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking), [Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration). These support the action/return contract, not any claim about actual network leakage.

End-to-end **NO-GO** remains: kernel-issued referenced \`EPROCESS\` with PID/creation epoch/start key/canonical EXE -> selected ALE_CONNECT_REDIRECT v4/v6 AppId/tuple/endpoint/compartment -> redirect context/records -> ALE_AUTH_CONNECT v4/v6/reauthorization -> accepted socket \`WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)\` -> kernel one-shot Witness/CLAIM -> new socket \`WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)\` -> verified SSH egress. Process death/PID reuse, 5-tuple reuse, sibling DIRECT, IPv4/v6, UDP/DNS/QUIC, and WFP/BFE/SSH failure are not proved. ETW/user-mode correlation or BFE inventory cannot close this chain.

## Next decisive experiment / safe gate

First **user-mode/read-only**: compile and execute R190's Rust BFE inventory on an explicitly admitted Windows 10 Pro x64 host; check whether readback AppId of *all four* relevant BFE filters exactly equals the separately armed route name and whether the mismatch can be excluded by an authenticated, generation-bound control-plane policy. Existing R190 does not read ARM status; any control-plane binding must itself have explicit generation and ownership proof. Never set a filter or driver to force a mismatch without a separate owner decision and all driver/VNC/SYSTEM rescue/rollback gates.

Potential future fix is to replace the mismatch's bare return with an explicitly rights-aware fail-closed decision, but **no kernel code or WFP policy was altered** in this R&D cycle. The mismatch scenario is a **conditional architectural NO-GO**; final packet classification and no-DIRECT remain unknown. No main/release, beta, PR #56, runner, service, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, external repo, automation or paid operation was touched.
