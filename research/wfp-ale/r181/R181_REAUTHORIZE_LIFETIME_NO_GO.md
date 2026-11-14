# R181 — AUTH_CONNECT reauthorization cannot reuse consumed FBR3 evidence

Date: 2026-11-14. Independent WFP/ALE R&D; only research/windows-wfp-ale-attribution-20261107. NO PacketBound/G2/no-DIRECT/leak-free admission.

## Source-pinned conditional NO-GO

Read-only baseline research bcfd1d1e1ae174714964a1d7c2ff9f77173591bd; main 5b5afc2feeda2195f302380e615ba003d4906e09.

* policy_windows.rs, blob acf60334320d970f58af3349ee75fbaa59826602: terminating selected ORIGINAL_APP_ID TCP AUTH_CONNECT V4/V6 rule, no reauthorization phase scoping.
* redirect.rs, blob a093f049d162987981a957aac90db1014bc6ff09: auth_check denies FWP_CONDITION_FLAG_IS_REAUTHORIZE (0x4) before Book::attest; auth_classify requests BLOCK on false.
* handoff.rs, blob e1d17217db50362ba9c4efc83af820b6beb094cf: Book::attest refuses repeated attestation once auth_seen; Book::take makes slot live=false on CLAIM. Numeric endpoint tombstones do not contain an AuthorizedFlow receipt.

**New constraint beyond R180:** merely permitting the reauthorization flag cannot make the current one-shot Book attest again. After initial AUTH it is already marked auth_seen; after CLAIM the ticket is gone. If a later Windows reauthorization for a selected connection reaches the existing terminating AUTH rule, the source requests BLOCK. This is a conditional availability failure, not a demonstrated Windows packet drop or an actual leak. A blanket permit of the flag / original AppId / loopback would discard the provenance constraints and is not an acceptable workaround.

Microsoft documents reauthorization at ALE on policy changes, arrival-interface changes, and IPsec re-key; classification can occur with a packet direction different from the original flow. REAUTHORIZE_REASON is not an authenticated FBR3 receipt.

## Executed deterministic negative tests

Local commands: python -m unittest -v test_r181.py; python -O -m unittest -q test_r181.py; python -OO -m unittest -q test_r181.py; python r181_reauth_matrix.py > python.jsonl; node r181_reauth_oracle.mjs > node.jsonl; cmp python.jsonl node.jsonl.

8/8 Python tests per mode. Independent Node.js oracle exactly matched 60/60 ordered JSONL rows; zero mismatches; SHA256 of canonical matrix: 04bdea42a7fd86fe3aedb85f68c5228e6ea8cb8e3975bcc683e3518a9b11c188.

Matrix spans IPv4 and IPv6, three ticket phases (issued, attested, claimed), five synthetic flow identities (selected redirect, sibling DIRECT, proxy SSH, reused endpoint, reused PID) and healthy/lost states. Strict R19 flag predicate BLOCK_REAUTH in all 60 conditional callout inputs. Removing the reauth bit guard alone yields 2 initial-unattested candidates (which are not normal reauthorization) and 58 denies; all post-auth and post-CLAIM remain denied. Unsafe proposed app+loopback bypass would admit sibling DIRECT and stale identities in constructed counterexamples.

These are model scenarios, not native Windows event counts, and deliberately include combinations the OS might never emit. No Rust compiler, kernel or WFP runtime, filters, packets or traffic tests used.

## Trust boundary / next decisive experiment

Still required: referenced PEPROCESS/FileObject + PID/creation epoch/start key/canonical EXE, native ALE_CONNECT_REDIRECT V4/V6 AppId/compartment/endpoint, FwpsQueryConnectionRedirectState0, kernel-owned transaction ID, ALE_AUTH_CONNECT honor/effective/proxy/reauthorization phases and original destination, redirected accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT, exclusive durable Witness ACK, one-use CLAIM, outbound SSH socket SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, BFE/SSH revocation and sibling DIRECT/DNS/UDP/QUIC coverage.

Next: clean-room user-mode Rust state machine for a *separately retained* per-flow authorization authority: transaction ID, endpoint+generation, process+epoch+canonical EXE, compartment, family/destination, original-vs-proxy, ACK/CLAIM epochs, liveness, and revocation. Independently test initial/honor/reauth sequencing, reverse-direction reauth, BFE/SSH loss, PID+5-tuple ABA and DNS/UDP before any native driver test. Native experiments remain gated on explicit owner approval and all driver/VNC/SYSTEM rescue/rollback requirements. Overall architectural WFP/ALE: NO-GO.

Official Microsoft sources:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v6_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags

No main/release/beta, PR #56, runners, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repos, automations, driver/callout, NDISRD, VNC, signed-driver work, vendor/C++/ProxiFyre/PR40 or paid operations touched.
