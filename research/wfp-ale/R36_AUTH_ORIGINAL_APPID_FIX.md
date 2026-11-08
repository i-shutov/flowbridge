# R36 — original AppId at ALE_AUTH_CONNECT; no current-AppId equality requirement

Research branch `research/windows-wfp-ale-attribution-20261107`; parent `455d9e730a2fcaaf44433e16b3740d4e64055847`.
This changes the **actual** R26 kernel callback and BFE activation code, not an isolated model. No driver load, certificate/signing bypass, BFE live-filter installation, release/main/beta mutation.

## Source-level correction
Microsoft defines `ALE_ORIGINAL_APP_ID` as the originating process for proxied connections; it can differ from the `ALE_APP_ID` of the currently executing process. The R26 callback required *both* fields to equal the selected EXE, and its AUTH filter was scoped only to current AppId. This could miss an original selected flow, depending on actual Windows callback stages.

- The AUTH BFE rules now match `FWPM_CONDITION_ALE_ORIGINAL_APP_ID` with the exact selected WFP blob and TCP. The redirect rules keep `FWPM_CONDITION_ALE_APP_ID`.
- The kernel AUTH callback checks the original AppId against the pinned selected image and ensures the current AppId is nonempty, bounded and well-formed, but **does not demand equality of current and original**.
- The same callback still demands WFP redirect flag, original destination, local redirect target PID, transport endpoint, PID, referenced process identity with creation epoch/start key and its once-issued ticket. Mere AppId equality does not authorize anything.
- `kernel/src/auth_appid.rs` is a new pure kernel-consumed predicate, compiled as part of the driver and executed as seven extra user-mode Rust tests during Windows CI. It verifies the genuine proxied current!=original case, wrong original, malformed current and unknown selected.

## Unresolved native liveness/security boundary
This deliberately does NOT infer the processId semantics of every stage of an actual redirected Windows connection. Because `ORIGINAL_APP_ID` can propagate to the broker's outbound socket via WFP redirect records, the AUTH filter may also see broker-side traffic. Our callback will deny any such observation without the original selected process/epoch/ticket, which is safe for that classified flow but **may block the proxy leg**. We must inspect actual native AUTH callback ordering and avoid using an unproved self-permit shortcut.

R35 session-local endpoint tombstones remain in force. Cross-load endpoint ABA is unresolved. R37 must independently authenticate the local SOCKS/SSH peer and show that an authenticated SSH session carries the application bytes; port and SOCKS NOAUTH alone are insufficient.

This is a compile/runtime-logic milestone, not G2 PASS. `g2_pass=false`, `release_accepted=false`, `system_no_direct_proved=false`.

Microsoft references:
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ne-fwpsu-fwps_fields_ale_auth_connect_v4
