# R37 — WFP-record-tagged, host-key-pinned SSH handoff

Date: 2026-11-08. All work exclusive to `research/windows-wfp-ale-attribution-20261107`.
Main and beta PR #56 untouched. R35/R36 remain separately tracked.

## Actual implemented transport, not a security model

R33 proved the research broker's previous `connect(127.0.0.1:ssh_port)` + SOCKS5 NOAUTH had no connection-bound SSH listener identity. R37 implements a concrete replacement in a new `trusted-ssh-r37` Rust crate and wires it into the actual experimental Windows broker:

1. The existing broker accepts a redirected socket and privately owns WFP redirect records and context. `Received::claim_and_connect_trusted_ssh` consumes this object and terminally CLAIMs the exact kernel ticket.
2. Only after CLAIM does it create a physical TCP socket. It calls `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` **on that exact physical socket before TCP connect**. On failure it cannot relay app bytes.
3. The physical socket is owned by `TrustedSshRelay`; `relay_over_pinned_ssh` consumes it and uses `russh::client::connect_stream` (Russh 0.65.1, pinned dependency). Host key bytes are matched to an externally supplied pinned OpenSSH public key, host certificates are explicitly rejected. User private-key authentication must succeed before `channel_open_direct_tcpip(original_IP,original_port)`.
4. Only after SSH channel open does the code copy application bytes bidirectionally. There is **no** substitutable local SOCKS listener in this R37 trust path. The old `--serve-admitted-lab` / SOCKS NOAUTH pathway is disabled for BFE policy activation; `--serve-research` remains a no-policy diagnostic baseline.

The new opt-in lab entrypoint `--serve-pinned-ssh-lab` still requires an externally admitted exact signed driver and environment. The code does **not** verify driver signature, recent VNC, SYSTEM rescue or physical egress by itself. No executable in this report was deployed, signed or loaded in kernel.

## Measured independent native user-mode SSH result

- Source `697356cded5d3bfac5ad7e7f35c28a360f962844`.
- [Actions #42448410446](https://github.com/i-shutov/flowbridge/actions/runs/42448410446): Linux **real isolated OpenSSH** test completed SUCCESS, native Windows crate compiled and tested SUCCESS.
- Independent original Linux artifact ID **13604891533**, GitHub artifact SHA256 **84900e3f13052040e5855f4e5ae31fde33b8aa199f3c8f9e9d9e5262f56cbbae**, independently verified ZIP CRC.
- Exact responses over authenticated SSH direct-tcpip for IPv4 and IPv6 PASS. Deliberately wrong pinned host key rejected; no application bytes reached test origin. Ephemeral fixture keys/processes removed.
- The first Linux fixture falsely called an expected `ConnectionResetError` under rejected host key an unknown failure. Source fixed in commit `697356cd`; failed run preserved.

This verifies host-key-pinned SSH **transport**, not the kernel redirect chain: `kernel_redirect_executed=false`, `wfp_records_forwarded=false`, `g2_pass=false`.

## Windows broker integration / honest build checkpoint

- `fd2ec0ca85b3fb708192f586fef8f2f65e14c2a5`: actual broker source consumes WFP receipt and applies records to physical SSH socket; depends on exact Russh/Tokio crate, adds exclusively trusted lab mode and disables untrusted SOCKS lab policy activation.
- `2cb1387bf5b8680be90230b719c351dcf76c9cdb`: exact trusted SSH dependency sources added to retained build manifest (no source-provenance omissions).
- The first integrated no-load Windows workflow (run 42448631821) compiled the kernel and broker but failed a **compile-negative test harness** that ran standalone `rustc` without new actual Cargo `russh`/Tokio external libraries, not a production compiler error.
- `bca1ec5907d77875a94f7d0d3cb011ce1ab4356b`: replaces test harness stubs/omissions with exact real Cargo-built `.rlib` linkage and adds two negative checks for private trusted-socket and uncloneable receipt.
- Verification run for this source is [Actions #42448939810](https://github.com/i-shutov/flowbridge/actions/runs/42448939810). At report creation it is pending; **do not claim PASS until it actually completes**.

## Remaining G2 barriers — DO NOT PROMOTE

The source implements `EXE → ALE_CONNECT_REDIRECT → AUTH → accepted socket/context → terminal kernel claim → WFP-record-tagged SSH TCP socket → pinned-key SSH direct-tcpip`. But there is NO loaded signed driver or physically observed *same-flow* end-to-end result. R35 4096 non-evicting endpoint tombstones are one-driver-lifetime safety, not a production long-lifetime design. R36 original/current AppId filter stage may block broker physical outbound (requires live Windows WFP AUTH trace). A dynamic BFE session cannot assert crash-persistent system no-DIRECT. DNS/UDP/QUIC, IPv6 physical egress, PID/process lifetime, endpoint ABA across driver loads, WFP failure and negative sibling/direct escape remain open.

First legitimate R38/R39 gated experiment requires accepted signature of exact `.sys`, fresh VNC, independently working SYSTEM rescue, rollback, signed package fingerprint and independent physical network capture. No test signing, SecureBoot/Defender changes, service/filter load or paid new infrastructure occurred here. G2 OPEN, release NO-GO; G1 dd1ab3c is not transferable. The next success metric is **one original unprepared EXE connection** whose driver receipt and authenticated SSH exact response are verified together, not more model checkpoints.

Primary APIs: https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records ; https://docs.rs/russh/0.65.1/russh/client/fn.connect_stream.html ; https://docs.rs/russh/0.65.1/russh/client/trait.Handler.html
