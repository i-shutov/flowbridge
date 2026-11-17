# R213 — Conditional self-block of the physical SSH leg by the selected ORIGINAL_APP_ID AUTH filter

2026-11-17. Independent branch only. **Architectural NO-GO / native proof pending.** This is a source-and-documentation-derived **conditional** liveness blocker, not an observed Windows failure, direct-route leak, or PacketBound/G2 pass. Nothing was installed, activated, or connected.

## Four pinned source boundaries

- `kernel-r19/policy_plan.rs` Git blob `0c3d0e88eb9d06f4030131d9533da2d629dbdab0`: a terminating selected-app AUTH filter is installed for V4 and V6, with a separate redirect filter.
- `kernel-r19/policy_windows.rs` `acf60334320d970f58af3349ee75fbaa59826602`: AUTH filter matches **`FWPM_CONDITION_ALE_ORIGINAL_APP_ID`** and TCP (`IP_PROTOCOL=6`), without a separate physical SSH leg condition.
- `kernel-r19/broker_windows.rs` `329ef14b63e70226bfad7372b0014559213abd04`: in `claim_and_connect_trusted_ssh`, the physical **IPv4** TCP socket receives `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` **before** connecting to the SSH server; an original IPv6 target still uses this IPv4 transport.
- `kernel-r19/kernel/src/redirect.rs` `a093f049d162987981a957aac90db1014bc6ff09`: the AUTH predicate demands redirected flag, loopback remote, local broker port, selected original AppId, referenced owner and matching ticket; failed predicate causes `BLOCK`.

## Conditional counterexample (no kernel classify claimed)

Microsoft describes `ALE_ORIGINAL_APP_ID` as the original application's full path for **proxied** connections, and the redirect-record IOCTL as carrying records onto the outbound socket. Suppose the physical SSH socket presents **original AppId = selected executable** after its WFP records have been set. The selected-original-AppId TCP AUTH filter then also matches the broker's physical SSH connection. Its remote destination is the SSH server, **not** the loopback broker listener; the AUTH predicate rejects it. A terminating AUTH callout blocks that connection when entitled to write `BLOCK`.

The broker's *current* AppId being different does **not** exempt this socket, because the filter is keyed to **original** AppId. This is distinct from the previous post-ISSUE race R212: the possible result here is **the intended SSH path being denied**, even while a selected client was redirected correctly. If WFP does **not** propagate selected ORIGINAL_APP_ID to the physical leg on the tested OS/stack, the AUTH filter does not match and this particular self-block does not arise. An AUTH action-write / filter-arbitration result must also be confirmed natively. No claim is made that such a failure has happened.

The ordinary selected-to-loopback AUTH case can pass the symbolic predicate; the selected-app UDP case and same-basename sibling remain **outside scope**, not safe from DIRECT. There is no proof for reauthorization, endpoint closure, process death/PID reuse, reused 5-tuple, compartments or WFP/SSH loss.

## Executable negatives and limits

`python3 research/wfp-ale/r205/r213_upstream_self_block_negative.py --source`

`node research/wfp-ale/r205/r213_upstream_self_block_oracle.mjs --source`

The independent Python and Node.js oracles model the **stated assumption** rather than inventing a physical observation: selected original AppId on the physical IPv4 SSH leg leads to terminating AUTH block, while absent propagation is a control. Both include original target V4/V6 (the physical R37 transport remains V4), genuine loopback AUTH, sibling and UDP controls. Pinned-source mode checks the exact Git blob SHAs and the 11 guards above. Offline models cannot establish that WFP actually supplies the assumed AppId/metadata and arbitration outcome. These scripts never open WFP, SSH, sockets or the network.

## Decisive gates

1. **Allowed first:** on approved Windows, read-only inspect existing BFE filters and current AppId/record semantics; run R201/R202/R203v7 read-only. This cannot prove physical classify ordering or absence of the self-block.
2. **Only with separate owner approval and all driver/VNC/SYSTEM rescue, rollback and cost gates:** trace `ALE_AUTH_CONNECT_V4` for the original redirected socket and the record-bearing physical SSH socket. Record exact `ALE_ORIGINAL_APP_ID`, `ALE_APP_ID`, flags (`IS_CONNECTION_REDIRECTED`, `IS_PROXY_CONNECTION`, `IS_REAUTHORIZE`), PID/creation epoch, endpoint, compartment, destination, filter and final disposition. The two sockets must not be joined by a 5-tuple/timestamp heuristic.
3. **Design constraint:** simply narrowing the selected AUTH rule to `IS_CONNECTION_REDIRECTED` would remove the sibling DIRECT guard; solve the original selected-app admission and broker physical egress scopes **together** with verified WFP precedence and revocation semantics.

Official Microsoft contracts:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_

NO driver/callout activation, filter changes, beta, PR #56, infrastructure, runner, firewall, defender, network, automations, or protected refs. **PacketBound/G2 PASS, leak-free/no-DIRECT and historical G1 are not asserted.**
