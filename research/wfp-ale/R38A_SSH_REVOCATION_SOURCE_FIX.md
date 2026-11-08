# R38A — terminate authenticated SSH relay on kernel lease loss (implementation)

Research branch only, base `c68c3d0271a01e56d6c7863ea8e0d7315d4da824`.

## Source change, not just a model

- `trusted-ssh-r37/src/lib.rs` now accepts an owned Tokio `watch::Receiver<bool>` revocation capability in `relay_over_pinned_ssh`.
- A sticky revocation signal races **every** stage: SSH host-key negotiation, user authentication, remote direct-tcpip channel opening, and actual `copy_bidirectional`. The signal has biased selection priority. Closing the channel sender is a revocation, never a permit.
- `copy_with_revocation` is a separate executable async Rust unit with negative tests for stop-before-copy, stop-during-pending-copy and sender loss. The old 60-second data-path timeout is retained as a separate bound.
- `broker_windows.rs::TrustedSshRelay::relay` passes the same receiver to the host-key-pinned SSH transport; it does not re-create a trusted capability from an address or snapshot.
- `broker.rs` creates a watch channel before start. Kernel PING failure, STOP failure, policy activation failure, broker accept error, worker error, connection-cap refusal, test timeout or shutdown broadcast `true` and set the existing shared atomic stop. Workers subscribe before they start; a later subscriber also reads the terminal flag.

These are user-mode revocation semantics, not proof that the OS has flushed previously queued bytes or closed physical DIRECT paths. A client can still have bytes queued in the kernel at the instant of lease loss. A broker process crash can still remove its dynamic BFE filters. **No system-wide fail-closed or G2 PASS is claimed.**

## QA and hard constraints

The source contains no new test-signing settings, driver installer, BFE filters, service changes, privileged runner operations or signing secrets. The existing hosted Windows and isolated Linux SSH CI remain build-only for the .sys. A successful build must not be described as an actual WFP redirect.

A single live positive/negative SSH test with a mid-stream kernel-equivalent STOP signal is still required for stronger evidence than the new deterministic Tokio async unit tests; the actual kernel heartbeat needs a signed, admitted Windows host. This change may interrupt a confirmed SSH session within the watch scheduling boundary; it cannot prove *zero physical packets after revoke*.

Next R38B: exact-source attestation signing package and read-only host signature/VNC/SYSTEM-rescue/rollback preflight. R39 remains gated until a valid Windows-accepted signed driver, current rescue proofs and independent physical capture exist.
