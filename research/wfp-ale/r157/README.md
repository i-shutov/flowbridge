# R157 — WFP/ALE filter-coverage negative gate

Date: 2026-11-13; **research branch only**. Source-based input HEAD: `79bfc41cec5e875b9872600c3563a85ec2143db7`. Main observed: `5b5afc2feeda2195f302380e615ba003d4906e09`.

R19 creates four (V4/V6 × REDIRECT/AUTH) selected-app **TCP-only** WFP filters. The redirect rule matches `FWPM_CONDITION_ALE_APP_ID`, and the AUTH rule matches `FWPM_CONDITION_ALE_ORIGINAL_APP_ID`. Both also match `FWPM_CONDITION_IP_PROTOCOL=6`. The policy session is dynamic (`FWPM_SESSION_FLAG_DYNAMIC`), and Microsoft documents automatic object removal when that session ends.

**NO-GO (policy coverage):** The four rules do not cover selected-app UDP/QUIC/DNS, ICMP, or same-family sibling-original traffic; after dynamic session removal these four rules are absent. This is an exact **filter-predicate nonmatch**, NOT an observed DIRECT connection, traffic leak, successful outgoing connection, or proof about other Windows filter providers.

Run the self-contained read-only negative gate from the repository root:
```sh
node research/wfp-ale/r157/r157_negative.mjs .
```
It checks three exact Git blobs and source structural tokens, then projects 60 combinations (two families, three protocols, five app pairs, active/removed policy). For matching predicates, 4/60 match REDIRECT and 6/60 match AUTH; 52/60 match neither of these four rules. Note: both filters refer to *different ALE layers*; this does not say a single classify was hit by both. Selected TCP requires independent WFP metadata/ticket verification at AUTH.

The independent development checkpoint additionally executed Python normal/-O/-OO (7 tests each) and a separate Node oracle (60/60 match, zero discrepancies), with SHA-256 `45e2ba78b1b49a0d73fc05abfc98bfd7821558b9b1f1c7322d16c17c9a046ced`. This committed compact gate is a separate test of the same pinned filter-scope contract, not a native driver test.

Next decisive decision: define TCP-only product scope or separately design DNS/UDP and BFE-loss enforcement; neither can be claimed from the existing dynamic four-rule arrangement. PacketBound/G2, accepted-socket ↔ redirect-records ↔ CLAIM ↔ SSH linkage, process/endpoint/PID/5-tuple ABA, IPv4/IPv6 compartments, no-DIRECT/leak-free and native WFP remain **NO-GO**. No driver, filter, service, runner, network or protected branch was changed.

Official sources:
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
