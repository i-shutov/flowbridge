# R150 addendum — selected-only ledger cannot ARM the existing R19 broker

Critical integration finding: `redirect.rs::ioctl(ARM)` requires a birth-recorded
broker process in the same R19 `Ledger` via `lookup(pid)` and confirms that the
recorded kernel process reference equals `IoGetRequestorProcess(irp)`.
The broker itself is NOT the selected application (`ARM` rejects an identical
selected path). Therefore replacing the global registry with a single
*selected-only* registry would fail to ARM, even for a selected process
started after configuration. This is a concrete source-level incompatibility;
no Windows connection failure has been observed.

Correct design candidate must distinguish **two trusted process roles**:
(1) a pre-authorized broker whose birth and process-reference provenance is
retained, and (2) an exact selected AppId registered only after that broker
successfully configures the target, followed by a fresh target birth.
Unknown broker, wrong process pointer or epoch, broker=self-selection, and
selected app launched before ARM all remain fail-closed. A broker already
running before process notification was installed also lacks birth authority.

Two independently authored Python/Node deterministic trace models each
completed 1,023 identical synthetic rows, SHA-256:
`2ebaf25166a796918d975135b0ef848035a00bd87efac127b48064928989f03f`.
Python normal and `-O` had the same result; both were `--model-only` locally.
The exact Git blobs of `redirect.rs` and `lib.rs` were separately checked
through GitHub, but source-pinned local execution and native WFP were NOT run.

Commands from exact research checkout:

```sh
python -B research/wfp-ale/r150/r150_broker_bootstrap.py
python -O -B research/wfp-ale/r150/r150_broker_bootstrap.py
node research/wfp-ale/r150/r150_broker_oracle.mjs
```

Next design gate: prove broker provenance and admission before selecting the
application, then independently prove selected process epoch/start key/FileObject
and canonical WFP AppId. Neither a user-mode PID lookup nor a reused 5-tuple
is adequate. This is a proposed architectural contract, NOT a validated
kernel driver, WFP filter or release fix. Same full NO-GO restrictions apply.
