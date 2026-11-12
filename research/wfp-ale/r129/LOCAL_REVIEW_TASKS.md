# R129 bounded local tasks for small-model reviewers

Dispatch status: NOT DISPATCHED. This chat has no callable subagent/model-selection
executor; no second-model review, API usage, payment or asynchronous work is claimed.
The primary executor implemented the code and ran separately implemented Python
and Node checks. Those checks are independent programs, not independent people.

All tasks: i-shutov/flowbridge ONLY; branch
research/windows-wfp-ale-attribution-20261107; read the exact R129 published source.
No push, branch mutation, main/beta/PR56 access, driver/callout/filter creation,
network experiment, service/runner/security/automation changes or paid API calls.
Prefer an available small coding model selected by the owner; do not auto-upgrade.
Return findings with file/line, reproducible counterexample, severity, and proof limits.

## A — Windows API/FFI reviewer (read-only, no execution)

Inputs: r129_filter_get_by_key.rs; official Microsoft fwpmu.h documentation.
Verify exactly FOUR imported APIs, DWORD return handling (not NTSTATUS), GUID ABI,
null/error output handling, one free per successful result, engine close on exit,
no FWPM_FILTER0 dereference, exactly four expected keys in R19 order. Check
missing/denied/RPC distinctions and absence of enforcement claims.
Output: API_REVIEW.md only, no code mutation. Acceptance: report unsupported
assumptions instead of declaring Windows proof; no kernel-driver build.

## B — adversarial JSON/oracle reviewer (offline only)

Inputs: r129_negative.py, r129_independent.mjs, result schema in Rust/PowerShell.
Run deterministic tests; add local negative fixtures for reordered/duplicate keys,
integer overflow, bool-as-int, string booleans, missing summary, forged code/hex,
wrong diagnostic exit and close failure. Do not import the Python implementation
into the independent oracle. Check all 1,250 outcomes including nonzero live exits.
Output: TEST_REVIEW.md and suggested fixture diff; no change outside this directory.

## C — PowerShell 5.1/native compiler reviewer (approved Windows host only)

Inputs: FlowBridge-R129-ReadOnly-ByKey.ps1 plus the pinned exact Rust blob.
First use the PowerShell parser without executing. Then -CompileOnly and default
synthetic mode; no live BFE unless separately invoked with -RunReadOnlyBfe by owner.
Confirm no installation, PATH changes only in this process and restored, LF/CRLF
cannot alter trusted source, stdout/stderr separated, runtime JSON validated, and
errors never yield a positive protection verdict. Collect tool versions, file
hashes, logs and exit codes. Do not run R113 or R19/CI/driver scripts.
Output: NATIVE_REVIEW.json with exact source SHA and evidence paths. Mark every
unperformed action NOT_RUN; do not substitute static tests for Windows execution.
