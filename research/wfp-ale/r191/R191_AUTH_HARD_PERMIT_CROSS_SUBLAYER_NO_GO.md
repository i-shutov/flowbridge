# R191 — AUTH_CONNECT hard PERMIT: cross-sublayer arbitration NO-GO
Date 2026-11-14. Only branch research/windows-wfp-ale-attribution-20261107. Not beta, PR #56, release, PacketBound/G2, or a leak-free proof.

Research parent: 2c189273d05298bf34d9351bdfc72e3205251c2d; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09.
Source blob IDs: kernel-r19/kernel/src/redirect.rs a093f049d162987981a957aac90db1014bc6ff09; kernel-r19/kernel/src/lib.rs 53f5ce6faa0f9f591974287f38ea890cafeb0dd2; kernel-r19/policy_windows.rs acf60334320d970f58af3349ee75fbaa59826602; r190/main.rs 775762e773ad2b2577d83a9976ef068df708f3e4.

## Material finding
R19 redirect::auth_classify's successful ALE_AUTH_CONNECT branch emits FWP_ACTION_PERMIT and explicitly CLEARS FWPS_RIGHT_ACTION_WRITE. Microsoft documents this as a HARD PERMIT at the layer. The successful ALE_CONNECT_REDIRECT path instead restores the incoming right before PERMIT and has distinct override semantics. R190 inventories competing filters only in the same sublayer; it does not cover the arbitration of other sublayers at ALE_AUTH_CONNECT, where R19's sublayer has weight 0x7000.

Conditional example: selected TCP connection, live WFP/BFE, trusted AUTH receipt, R19 callout permits before a matching ordinary BLOCK in a LOWER-priority foreign sublayer on the SAME layer. Hard permit cannot be overridden by that ordinary block; soft permit could. A callout VETO, earlier hard block, or block at a different layer may still block. Relative priority and actual rules are NOT measured, so NO native Windows firewall bypass, leak, or PacketBound result is claimed.

Microsoft primary documentation:
https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ns-fwpsu-fwps_classify_out0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer

## Executed clean-room negative tests
Python arbitration_negative.py independently compared with Node.js independent_oracle.mjs. 512/512 byte-identical CSV rows, SHA-256 b88a70f7c71387d85c59843a879e81abc04d9400dcdca9b5abd9c5eb6a326ef4. Python unit tests 10/10 under normal, -O and -OO. Two conditional differences between hard and soft permit, one for IPv4 and IPv6; 256 BFE-loss UNKNOWN cases and 192 UDP/sibling OUT_OF_SCOPE cases. Results are SYNTHETIC classifications and never native packet observations. Rust compile/Windows WFP runtime was not performed. No kernel driver or filter was created, installed or run.

## Trust boundary / NO-GO
FwpmFilterGetByKey0, FwpmFilterEnum0, FwpmSubLayerGetByKey0 and FWPM_TXN_READ_ONLY can inspect static policy but cannot observe runtime FWPS_CLASSIFY_OUT0.rights, callback execution, or enforcement continuity. Required unproven proof chain: referenced EPROCESS / PID + creation epoch + canonical EXE -> ALE_CONNECT_REDIRECT v4/v6 / original destination and compartment -> endpoint and WFP redirect context/records -> ALE_AUTH_CONNECT including reauthorization -> real accepted socket WSAIoctl redirect receipt -> Witness / one-use CLAIM -> physical SSH socket with SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS -> authenticated SSH. PID reuse, 5-tuple reuse, sibling DIRECT, UDP/DNS/QUIC, process death and BFE/SSH failure remain NO-GO.

## Next decisive experiment
Allowed: independently compile the existing read-only Rust inventory on an admitted Windows 10 Pro and enumerate visible sublayers and filters on both AUTH_CONNECT layers; inspect weights, actions, ACL failures and competing providers, but NEVER infer actual hard-permit override from mere presence. A native WFP classify/veto experiment requires a distinct owner decision plus all driver/VNC/SYSTEM rescue/rollback gates; not carried out here. Decide the intended semantics of R19's hard permit before any production recommendation. Do not simply modify kernel action rights without a separate security review.

Only the research branch is changed; no drivers, filter operations, network/services/firewall settings, beta, PR #56, other repositories, runners, automations or paid operations.
