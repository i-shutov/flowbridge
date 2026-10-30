# Windows visual rule editor — native vertical acceptance

Scope: local **Win32** rule editing, no Electron and no system-interception claim.

- Use **Журнал и JSON → Правила…** to open the modal editor. A list preserves first-match order. Add/Copy create disabled rules, so an empty catch-all cannot unexpectedly redirect all traffic.
- Fields: ID, full application patterns, wildcard host patterns, IPv4/IPv6 CIDR lists, port ranges, enabled toggle, Direct/Block/Proxy/Chain actions, default action.
- Separate entries with semicolons. For a port range, use `8000-8010`; empty fields mean no restriction. **AND** across criterion types, **OR** within each list.
- Each edit uses the **existing strict Rust profile validation** (`fb_validate_json`), including unknown proxy/chain, unknown schema fields, network syntax, duplicate IDs, ports and 1 MiB profile size. Failed edits leave the last accepted in-dialog model unchanged. Cancel discards all modal edits; Save returns a validated *draft* to the JSON editor.
- Route changes are NOT activated until **Применить профиль**; its existing atomic engine reload/persistence and rollback remain authoritative. No WFP installation or UAC is attempted by this editor.
- The local explicit SOCKS5 listener does not attest the origin application's process identity. Applications and host criteria in native capture require actual OS-provided metadata; previously locally resolved DNS names cannot be reconstructed by this GUI.
- Real Win32 native smoke creates a rule with two hosts, ports 443 and 8000–8010, proxy action, performs an invalid 70000-port edit that must fail, commits, verifies with `fb_evaluate_json`, reopens and cancels, and checks dialog work-area bounds. The independent portable C++ model test covers atomic error rollback, Add/Copy/move/erase/default and profile preservation.

This milestone is **not** release 1.0: signed Windows WFP driver activation, Mac Network Extension and DNS packet evidence remain open. QA gate is exact-head Windows native build, installed GUI smoke and all existing Rust and macOS test jobs, not screenshot-only claims.
