# R141 — bounded junior-model review assignments (NOT DISPATCHED)

No callable small-model/subagent execution tool is available in this session. These are scoped assignments, **not** claims that another model ran, and no paid invocation is authorized. No Git mutation delegated.

A. **WFP lifetime and arbitration.** Read `R141_PERSISTENT_GATE_ARCHITECTURE.md`, R19 `policy_windows.rs` at blob `acf60334320d970f58af3349ee75fbaa59826602`, and Microsoft WFP object management, filter flags, provider startup and arbitration docs. Produce the smallest counterexample to the proposed persistent callout baseline. Review boot-time→BFE first start versus runtime BFE loss. Return a table with citation and file/line, no Windows changes.

B. **Offline model adversarial QA.** Run `test_r141.py`, compare Python/Node 192 state digest, try malformed JSON, string/number boolean substitutions and an explicitly unregistered callout with `PERMIT_IF_CALLOUT_UNREGISTERED`. Do not weaken a failing oracle to get green. Report exact broken invariant and negative fixture.

C. **Recovery/rollout independent reviewer.** Check staged on-call design (owner-only BFE object namespaces, persistence flags, provider service auto-start, separate local console, snapshot/rollback, protected selected-app DIRECT tests for both IP families, UDP/QUIC and system DNS). Identify which unproven gate is the earliest release blocker. No driver install, filter addition, service stop, firewall/registry changes or network testing on user's Windows.

Scope is solely `i-shutov/flowbridge`, `research/windows-wfp-ale-attribution-20261107`, `research/wfp-ale/r141`. `main`, beta, PR56, runners and automation settings are out of scope.
