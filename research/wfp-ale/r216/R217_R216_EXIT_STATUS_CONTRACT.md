# R217 — R216 negative-test exit-status integrity

2026-11-20. Scope: `i-shutov/flowbridge`, **only** `research/windows-wfp-ale-attribution-20261107`. Parent commit `34acc6f01d4f7a40fa5ae6c200882128a95ab15a`; read-only `main` `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Reproduced defect and fix

In R216's original Python oracle (blob `7083aa2b70ff9ef5210bb175d2ed395c1d289832`), the bottom-level `unittest.main(exit=False, verbosity=2)` permits **exit code 0 even when a test fails**. The script then prints the seemingly successful 12-row SHA-256 transcript. A detached reproduction with one intentionally failing `unittest.TestCase` confirmed `FAILED (failures=1)`, `exit_code=0`, and a success-like transcript printed afterward. This is an evidence-integrity defect, **not** a new WFP/classify finding.

The corrected Python runner explicitly checks `TestResult.wasSuccessful()`, exits nonzero for failure, and prints the canonical digest **only after** the four tests pass. The new independent Node.js subprocess verifier runs the clean Python script, checks its exit status and digest, then mutates the exact mapped-V6 guard in a disposable temporary file. It requires a nonzero exit, reports failing tests, and rejects any positive transcript after failure. The temporary file is always removed. Neither verifier uses any network or OS networking API.

Local commands and results (Python 3.13.5, Node 22.16.0):

```sh
python3 -m py_compile research/wfp-ale/r216/r216_dualstack_negative.py
python3 research/wfp-ale/r216/r216_dualstack_negative.py
node --check research/wfp-ale/r216/r217_harness_exit_verifier.mjs
node research/wfp-ale/r216/r217_harness_exit_verifier.mjs
node research/wfp-ale/r216/r216_dualstack_independent.mjs
```

Results: **4/4 Python PASS**, **12/12 Node source-policy cases PASS**; identical canonical transcript `bcb20d46677ab067651521c4c066c8bed5701d9321ae578a30d813c332c213dc`. The new independent subprocess verifier **PASS** (clean exit 0 and exact digest; mutated policy fails nonzero and prints no positive digest). The original false-green exit behavior was reproduced before patching. This does not execute Rust, Windows, WFP or classify.

## Security and trust boundary

The R216 architectural NO-GO is unchanged. Official Microsoft [ALE dual-IP semantics](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-) allow an IPv4-mapped IPv6 destination at the IPv6 ALE layer, while the R19 `Destination::valid` policy rejects it. R19 still lacks a proven `FWPS_CONNECT_REQUEST0.previousVersion` provenance check and a complete same-connection kernel-origin identity chain through `ALE_CONNECT_REDIRECT_V4/V6`, `ALE_AUTH_CONNECT_V4/V6`, accepted-socket `WSAIoctl` redirect context/records, terminal CLAIM and actual physical SSH. PID/epoch, 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, WFP/SSH loss, final arbitration and IPv6 mapped-context treatment remain NO-GO. See [R216](R216_DUALSTACK_IPV4_MAPPED_V6_NO_GO.md) and Microsoft's [FWPS_CONNECT_REQUEST0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0).

Next decisive permitted experiment: compile original pure-Rust R201/R202 and a mapped-V6 Rust parser model with independent oracles on an available toolchain, followed by authorized passive read-only BFE R199 on Windows. **No native kernel proof** or no-DIRECT/leak-free/G2 PASS is asserted. Driver/callout installation, filter changes, system/network/safety configuration, beta, PR #56, runner and automation changes remain forbidden.
