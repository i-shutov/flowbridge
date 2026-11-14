# R190 — same-sublayer competition and R188 inventory false confidence

Date: 2026-11-14. Repo i-shutov/flowbridge; only branch research/windows-wfp-ale-attribution-20261107. Research parent 5678117255782989db005d9749132c4a982c98db; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. Separate R&D: not beta, PR #56, release, PacketBound/G2 or leak-free proof.

## Material finding

R19 kernel-r19/policy_windows.rs installs four AUTH_CONNECT/CONNECT_REDIRECT filters in sublayer 1649f024-25b3-4e01-9ca1-5ca803010019 with FWP_EMPTY auto weight. R188 r188/main.rs (Git blob f11fd2227e57a72935d1646ef14b51c6b3cfd51f) verifies four GUIDs, layers, actions, TCP/AppId and bytes but does not verify weight/effectiveWeight or enumerate competitors in that sublayer.

Microsoft Filter Arbitration specifies that, within a sublayer, a matching higher-weight filter returning PERMIT or BLOCK causes lower-weight filters to be skipped. Thus, **if** a competing terminal filter matches and outranks R19 in the same sublayer, all four R19 objects may look correct while its callback is not reached. No actual competing Windows filter, packet path, or DIRECT leak was observed. Different layers/sublayers require separate arbitration analysis. Documentation: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration ; https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0 ; https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment .

## Clean-room, read-only Rust candidate

main.rs extends R188 without filters/drivers/network operations. It checks weight.type == FWP_EMPTY, effectiveWeight.type == FWP_UINT64 and nonzero filterId, uses FwpmFilterCreateEnumHandle0/FwpmFilterEnum0/FwpmFilterDestroyEnumHandle0 inside FWPM_TXN_READ_ONLY, and refuses positive structure observation when *visible* non-R19 filters share its sublayer and relevant layer. Limit: 32768 enumerated objects; errors/truncation => UNKNOWN, not success. BFE enumeration is ACL-filtered, a transaction snapshot rather than an enforcement fence. It does not prove no hidden filter or callback reachability. Official API: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0 and https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0 . Rust source NOT compiled; Windows BFE NOT run.

## Independent deterministic negative tests

Python unittest normal/-O/-OO: 6/6 each. Independent Node oracle: 480/480 agreement, matrix SHA256 a94c1fcba108d7865ad1b45467ca26c2189271fced77dcbb91a26314423ea58c. Model: 4 layer/family cases x 3 weight forms x 5 competitor visibility/priority states x 2 AppId x 2 BFE x 2 callout registration flags. R188 structural acceptances 60, of which 24 have modeled shadowed callbacks; stricter R190 acceptances 12, of which 4 still have a modeled *hidden* high-priority competitor. Synthetic counterexamples, NOT observed Windows events or measured leak rates. Mutation guards cover both new assertions.

## Required trust chain and next decisive experiment

Kernel-origin process (referenced EPROCESS, PID + creation epoch + canonical EXE) -> ALE_CONNECT_REDIRECT v4/v6 original AppId/destination/compartment -> redirect context -> ALE_AUTH_CONNECT including reauth -> actual accepted socket WSAIoctl redirect records/context -> unique ticket + Witness ACK/CLAIM -> outbound SSH socket and verified physical path. PID death/reuse, 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC and BFE/SSH loss remain NO-GO. Never replace kernel evidence with ETW/PID/5-tuple correlation.

Next: independently compile this exact Rust candidate on an admitted Windows 10 Pro x64 host, compare read-only enumerations (ACL, filterId, effectiveWeight and visible competitors), report OS/rustc/source/binary SHA and exit codes. Do not install test filters or activate drivers; callback or leak testing requires distinct owner decision and driver/VNC/SYSTEM rescue/rollback gates.

No other Git ref, runner, beta, PR #56, service, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, paid operation, vendor binary, ProxiFyre/closed PR40, automation or controller is touched.
