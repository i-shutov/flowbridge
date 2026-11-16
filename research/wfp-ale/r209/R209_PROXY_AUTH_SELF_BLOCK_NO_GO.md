# R209 — tagged SSH AUTH self-block, conditional source-level NO-GO

2026-11-16. Scope: research/windows-wfp-ale-attribution-20261107 only. Not beta, PR #56, PacketBound/G2 or release acceptance.

## Cross-layer counterexample

1. In R19 policy_windows.rs, AUTH_CONNECT_V4/V6 uses a terminating callout scoped by FWPM_CONDITION_ALE_ORIGINAL_APP_ID = selected image and IP_PROTOCOL = TCP (lines 45-70).
2. In R19 broker_windows.rs, Received::claim_and_connect_trusted_ssh attaches WFP redirect records with WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) **before** connect() to the SSH host (lines 122-160).
3. Microsoft documents ORIGINAL_APP_ID as the original application's path on proxied connections; redirect records link proxy egress to the original.
4. In R19 redirect.rs, auth_check for *every* matching AUTH indication only admits redirected traffic to exact broker loopback and broker port with selected original-process metadata and a ticket (lines 154-245). Failed auth_check invokes block() (lines 139-151).

**Conditional contradiction:** if the record-tagged physical SSH socket carries the selected ORIGINAL_APP_ID at ALE_AUTH_CONNECT (as documented for proxy connections), it matches the same AUTH filter, yet its remote destination is the SSH server, **not** the local broker port. The callback requests BLOCK. Thus the policy can self-block the tagged SSH egress. This is NOT a live WFP classify observation or demonstrated leak; actual metadata and final verdict remain unproved. If ORIGINAL_APP_ID is absent instead, this selected-AppId rule does not protect that egress, which is not acceptance either.

Source exact Git blobs read from research HEAD e00efd73a1cac56708c0a7167166e637f40012d7:
- research/wfp-ale/kernel-r19/policy_windows.rs  acf60334320d970f58af3349ee75fbaa59826602
- research/wfp-ale/kernel-r19/broker_windows.rs  329ef14b63e70226bfad7372b0014559213abd04
- research/wfp-ale/kernel-r19/kernel/src/redirect.rs  a093f049d162987981a957aac90db1014bc6ff09

Independent source audit: 8/8 structural guards passed, including policy original AppId+TCP+terminating action, SET_RECORDS before connect(), exact loopback/port, kernel process lookup, and block-on-failed-auth.

Official contracts:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management

## Reproducible deterministic negatives

- python3 research/wfp-ale/r209/r209_self_block_negative.py : 9/9 PASS in standalone Linux user-mode.
- node research/wfp-ale/r209/r209_self_block_oracle.mjs : 9/9 PASS with an independent oracle.
- Both exercises are symbolic counterexamples with chosen input metadata, not native Windows, Rust, BFE or ALE classification.

The tests distinguish: original selected IPv4/IPv6 success, tagged physical SSH self-block, selected sibling DIRECT block, nonselected/untagged broker rule miss, UDP DNS TCP-filter miss, and broker-port spoof rejection. Source code remains unmodified.

## Trust boundary / next decisive experiment

Referenced process-birth EPROCESS+FileObject -> PID+creation epoch+start key+canonical EXE -> original ALE CONNECT_REDIRECT/AUTH_CONNECT IPv4/IPv6 -> accepted-socket WFP context/records -> terminal CLAIM -> physical SSH WFP records -> actual egress **is not demonstrated**. The R207 reauthorization and R208 closure stale tickets remain open. Also open: PID reuse, reused 5-tuple, sibling DIRECT isolation, IPv6, DNS/UDP/QUIC, WFP/BFE/SSH loss and dynamic-session removal.

NO-GO for coexistence of the tagged SSH socket with this exact AUTH policy until native evidence. Do NOT whitelist broker PID / SSH host, remove ORIGINAL_APP_ID, install callouts/filters, or claim leak-free. Safe next step: only independently admitted read-only Windows Rust R201/R202 and passive R199 BFE-readback. Confirming self-block requires explicit owner driver/VNC/SYSTEM rescue/rollback gates and a native dual-AUTH classify trace containing original/current AppId, remote tuple, endpoint handle, redirect flags and verdict for original vs tagged SSH socket. No system settings, drivers, filters or networks were touched in this cycle.
