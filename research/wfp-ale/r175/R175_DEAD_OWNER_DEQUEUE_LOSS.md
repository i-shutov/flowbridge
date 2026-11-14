# R175 — Dead-owner Witness pop destroys receipt identity

Date: 2026-11-14. Independent architectural R&D ONLY; not beta, PR #56, G2, driver or native WFP.

Pinned research parent: c6ffd2d782988887632d9eb8d54646d08864a0e5; read-only main: 5b5afc2feeda2195f302380e615ba003d4906e09.

Source blobs verified directly:
- kernel/src/ledger.rs: b88c4c9237c4c118517978fc454f5048f522aa7f
- kernel/src/lib.rs: 53f5ce6faa0f9f591974287f38ea890cafeb0dd2
- kernel/src/handoff.rs: e1d17217db50362ba9c4efc83af820b6beb094cf

Ledger::pop removes and advances an entry BEFORE checking owner_generation owner.live. Dead owner -> Err(Denied::Dead), but lost remains false. lib.rs::dispatch maps all pop errors to NOT_READY, 0 bytes: no receipt number. The next call can return SUCCESS for a later receipt. Dead-owner-only queue yields NOT_READY then EMPTY. This is a conditional protocol NO-GO if future consumer silently retries NOT_READY and admits later receipts without terminal revocation or explicit typed gap accounting. A fail-sticky consumer is possible, but at availability cost. Not a proven security exploit or DIRECT leak: R165 has no runtime producer; R173 has no broker consumer.

Reproduction: python3 r175_dead_owner_pop.py; python3 -O r175_dead_owner_pop.py; python3 -OO r175_dead_owner_pop.py; python3 r175_dead_owner_pop.py --matrix > py.jsonl; node r175_dead_owner_oracle.mjs > node.jsonl; cmp py.jsonl node.jsonl.

Executed local: 5/5 in each Python mode, Python/independent Node 96/96 byte-identical rows, zero divergences; purposeful sticky mutant diverges. Both IPv4/IPv6; dead-first/live-first/alternating; 1-4 dead and 0-3 live receipts. Matrix SHA256 5464adbd413d21e8d0948231d461f21643520bc60610a54236559255316b66cd. Source-gate of exact blobs PASS. NOT compiled Rust or run Windows, WFP, driver, filter, network, signed work.

Next decisive allowed experiment: implement a typed kernel transaction/receipt/tombstone ACK state machine in offline Rust user mode (without driver or networking), with separate independent oracle for crash-after-pop-before-ACK, process death, PID reuse, 32/33 capacity, endpoint ABA, reauthorization and SSH/BFE revoke. Choose whether OwnerDead is terminal or typed sequence-preserving drop. R165 producer, R172 exclusive reader, R173 backpressure, R174 join remain blocking. WFP original AppId, canonical EXE, compartment, IPv6 remote scope, accepted socket redirect context/records, physical SSH binding, sibling DIRECT and DNS/UDP are unproven; status NO-GO, no PacketBound/G2 PASS or leak-free claim.

Official references:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records

Protected branches, beta, PR #56, runner, security settings, service, network, firewall and automations untouched.
