# R204 — R199 BFE engine-code/exit consistency (NO-GO)

2026-11-16, independent WFP/ALE research only. Pinned research branch HEAD:
7631a5904189ba90949259909d4f317f06e2584d. Main (read-only):
5b5afc2feeda2195f302380e615ba003d4906e09.

## Substantive new negative result

Both R203v3 Python and independent Node evidence validators accepted a synthetic
R199 transcript with management-success state and engine_api_code=5, with
engine_api_code absent, or with UNKNOWN state and executable exit 0. This is
inconsistent with the pinned R199 main.rs Git blob
8a020d2addc8395d96af4e5c71f6d0428bbcc0e2.

R199 calls FwpmEngineOpen0. On failure OR successful status with NULL handle,
it reports UNKNOWN, the returned engine_api_code, and exits 3. On successful
engine open with valid handle, it reports MANAGEMENT_READBACK_NOT_PROOF,
engine_api_code=0, and exits 0. Neither classification is a kernel proof.

Two independent stdlib-only gates and ten cases each:

    python bfe_engine_contract.py --self-test
    node bfe_engine_oracle.mjs --self-test

For an R203 evidence directory where BFE was requested:

    python bfe_engine_contract.py --evidence-dir PATH
    node bfe_engine_oracle.mjs --evidence-dir PATH

Both gates enforce exact success and failure semantics, including the unusual
API-success-plus-NULL-handle case (UNKNOWN/exit 3/code 0). They complement the
full R203 source-hash validators; they do not certify source provenance,
actual Windows execution, kernel classification or end-to-end SSH.

A local R203v4 package patches both full validators and adds four adversarial
transcript cases. The local 25/25 dual-oracle synthetic campaign passed; the
original R203v3 validator logic demonstrably false-accepted 3 contradictions.

## Trust boundary

Referenced EPROCESS/FileObject -> PID/creation epoch/start key/canonical EXE
-> AppId -> ALE CONNECT_REDIRECT/AUTH_CONNECT v4/v6 -> accepted-socket WFP
context/records -> one-shot CLAIM -> physical SSH remains NO-GO. Also open:
process death/PID reuse, reused 5-tuple, sibling DIRECT, DNS/UDP/QUIC,
reauthorization, WFP/SSH loss. Do not assert PacketBound/G2 PASS or leak-free.

Next allowed experiment: offline Rust unit tests R201/R202 and optional passive
R199 BFE readback on an approved Win10 Pro x64 host, independently verified.
No driver, WFP filter/callout creation, services, firewall, security or
network changes. No beta, PR #56 or protected-branch changes.

Microsoft API: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0

R204 follow-up: BFE stdout is read as UTF-16LE (PowerShell 5.1 redirection)
when BOM/zero-byte framing is present, and UTF-8 otherwise. Local tests
independently accepted a valid UTF-16 management transcript and rejected
the same transcript after engine_api_code changed from 0 to 5.
