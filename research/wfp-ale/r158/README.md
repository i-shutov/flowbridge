# R158 — WFP filter AppId / ARM selected-target split (negative gate)

Source-level architectural NO-GO, **not** a witnessed DIRECT/leak or native WFP test. Exact parent examined: `c44e229ecb5821114a4bd77d351e388cf5cf0be2`, `main` observed `5b5afc2feeda2195f302380e615ba003d4906e09` on 2026-11-13.

The R19 dynamic filters select `Plan.appid` at `ALE_CONNECT_REDIRECT` (`ALE_APP_ID`) and at `ALE_AUTH_CONNECT` (`ALE_ORIGINAL_APP_ID`), TCP/6. Separately, `redirect.rs::ioctl(ARM)` stores target EXE bytes from the request, validating the broker process and inequality with the broker name, but **not equality with the WFP filter AppId**. For legitimate broker C, policy EXE A and ARM EXE B, B's TCP/IPv4 and TCP/IPv6 do not match **either of these four filters**. A/A and B/B are controls. This does not establish an actual product configuration mismatch or a permitted packet; other filters may apply.

Run from the exact checked-out branch root, without drivers, network experiments, or WFP mutation:

```sh
node research/wfp-ale/r158/r158_negative.mjs .
```

The executable verifies three immutable R19 Git blobs, then checks 144 cases: 2 IP families × 2 protocols × 2 policy targets × 3 ARM targets × 3 origin targets × 2 BFE policy states. Four active-policy TCP selected-target mismatches are found; matrix SHA-256 `41c6f7e594823657eaab70da86075a12f6aec4928d63b26e0c3bc668514a7d45`. Independent Python model and Node oracle: 144/144 match, 0 discrepancies; Python normal/-O/-OO: 9/9 each; source and model mutation rejected. Supplementary checkpoint contains those independent scripts and full logs. These are offline model results, not kernel proof.

Admission must bind the **same canonical AppId byte domain** through `FwpmGetAppIdFromFileName0` → WFP filter readback (`FwpmFilterGetByKey0`) → ARM selected-name before traffic eligibility. Even that equality is not proof of `PEPROCESS`/FileObject provenance, process epoch, endpoint or compartment lifetime, `ALE_AUTH_CONNECT` verdict, redirect records, CLAIM, SSH delivery, or no-DIRECT. IPv4/IPv6, PID reuse, endpoint ABA, reused 5-tuple, sibling DIRECT, DNS/UDP/QUIC, WFP/BFE/SSH loss remain NO-GO; PacketBound/G2 PASS and leak-free are not claimed.

Next allowed decisive step: Windows x64 **read-only** comparison of API-returned canonical AppId, ARM bytes and the two-family live BFE filter snapshots. Any native callout/driver proof requires separate owner gates.

Official: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0 ; https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
