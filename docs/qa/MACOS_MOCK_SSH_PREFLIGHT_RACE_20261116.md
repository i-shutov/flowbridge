# FlowBridge — macOS CI readiness-test port collision, 2026-11-16

## Reproduced failure

On [cross-platform CI #43822796200](https://github.com/i-shutov/flowbridge/actions/runs/43822796200), the macOS 15 arm64 workspace run failed one Rust unit test, `flowbridge-tunnel::tests::readiness_requires_child_and_socks_and_stop_reaps_without_restart`. The test's fake SSH supervisor returned `state=failed`, `attempt=0`, `pid=None`, with `local SOCKS port 24959 is unavailable: Address already in use (os error 48)`.

The test's `config()` allocates a host port via bind/probe/release. A second CI process or another test executable can claim it before the separate fake-SSH child starts. This is the verified failure *class*, not evidence that production OpenSSH or WFP broke, nor proof of a specific external process. The failure does not justify weakening actual product binding rules.

## Bounded test-only correction

The affected readiness unit test now uses the **already existing** helper `started_mock_with_preflight_retry(config(), "healthy")`, instead of directly using `supervisor(config, "healthy")`. That helper:
- retries at most three times, selecting a new checked port, **only** when the pre-child failure is an exact `Address already in use`/OS error for the same configured port;
- requires `status=failed`, `pid=None`, `attempt=0`, `restarts=0` to guard against retrying a real spawned child or unrelated failure;
- drops/joins failed fixture supervisor before retry; never changes the production `Supervisor`, tunnel state machine, SSH arguments, network policies, helper process or driver;
- returns only when an actual mock child responds to the SOCKS readiness probe; the readiness test still asserts `ready`, attempt=1, restarts=0, owned child PID and successful stop/port rebind.

Existing `mock_preflight_collision_retries_before_spawning_child` and `mock_preflight_collision_filter_rejects_unrelated_failures` tests exercise both the positive bounded retry and negatives for wrong port, started child, denied permissions and failed health probes. No new external dependency is introduced.

## Evidence/acceptance

Source baseline: `main` commit `5b5afc2feeda2195f302380e615ba003d4906e09`, preserving the isolated WFP Draft PR #72 and frozen beta unchanged.

Required acceptance: cross-platform `cargo test --locked --workspace` and full macOS native workflow green on **the exact changed source**, without test suppression, `--skip`, ignored failures, broad retry around Cargo, or release-gate waivers. Green hosted tests do not substitute native owner Mac A4, WFP G2 or 1.0 acceptance.

**Status:** `MACOS_MOCK_SSH_PREFLIGHT_RACE=PATCHED_PENDING_CI`, `G2=NO_GO`, `RELEASE_1_0=NO_GO`.
