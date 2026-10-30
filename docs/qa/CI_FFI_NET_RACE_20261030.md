# CI race diagnosis — source-only test fixture corrections

## Evidence

The same production bits gave opposite outcomes in consecutive OS jobs:

- [main Rust/native run 41034622006](https://github.com/i-shutov/flowbridge/actions/runs/41034622006) failed on **macOS 15** in
  `native_preparation_binds_the_actual_socket_before_connect` at
  `crates/flowbridge-net/tests/transport.rs:868`. A native **nonblocking**
  `std::net::TcpListener::accept().unwrap()` returned macOS
  `EWOULDBLOCK` (35) immediately after the async connect returned.
- [main Rust/native run 41035203285](https://github.com/i-shutov/flowbridge/actions/runs/41035203285) failed on **Ubuntu** in
  `gate_ffi_validates_strict_input_and_checked_engine_handles` at
  `crates/flowbridge-ffi/src/lib.rs:1340`, expected gate `ok=true`, observed
  `ok=false`. That test used shared endpoint `127.0.0.1:1080`,
  simultaneously used by other pool and admission tests.
- The exact PR #35 [five-job pre-merge CI](https://github.com/i-shutov/flowbridge/actions/runs/41034750582) was all-green, corroborating nondeterministic fixture interference.

## Changes under review

1. The FFI gate-only test now uses `127.0.0.1:11983` with no actual network.
   Other tests continue to deliberately share `:1080` to verify product
   admission behavior; **no** production global-budget guarantee was changed.
2. A macOS/Linux native preparation test retains its original **before
   connect** no-SYN assertion but polls the nonblocking fixture listener
   for at most two seconds after real connection, with 5 ms bounded async
   intervals. Unexpected socket errors and deadlines still fail CI.

Both corrections preserve actual Rust API semantics and negative rejection
tests. Passing CI on the exact new SHA is still required; no wholesale test
disabling, `--test-threads=1` workaround, production budget removal, or
system configuration change. Windows WFP, macOS NE and DNS remain distinct
native acceptance requirements.
