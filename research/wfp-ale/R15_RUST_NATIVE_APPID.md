# R15 — native Windows Rust WFP AppId probe and independent Win32 comparison

Research-only branch: research/windows-wfp-ale-attribution-20261107. Date: 2026-11-07.
Single-use GitHub-hosted Windows-2025 job; no self-hosted runner, driver, callout, WFP filters, services, firewall, Defender, VNC, kernel traffic, automation or release mutation.

## Authenticated native execution

| Field | Value |
|---|---|
| Source commit | c2c2f8572e20979d6aeec8a0116f27bdfd6dbd9e |
| Windows GitHub Actions | 42366954519, SUCCESS |
| Job | 128386911960, SUCCESS |
| Artifact ID | 13571679812 |
| GitHub artifact SHA256 | 83f6dbbacef09ad6bd0d30ce3fb0fece7864566c6329647ffa8cb47b8c298b13 |
| Rust source Git blob | 1f71e0a85960bbab66b560dbf91849d838fdaffd |
| Python source Git blob | 9421be67d5fd977ceab334830be2cc83b4135c27 |

Windows compiled the dependency-free Rust user-mode appid_readonly.rs with rustc --edition=2021 -Dwarnings. Both that executable and the independent Python ctypes implementation called FwpmGetAppIdFromFileName0 on the same local fixture paths. Five of five equality and blob-length comparisons agreed. Python made 10 real WFP AppId reads. The Rust program exposes equality and byte counts, **not raw AppId bytes**: no full independent cross-language byte-by-byte evidence is claimed.

| Pair | AppId equal by both implementations? |
|---|---|
| Same file/path | YES |
| Identical EXE with same basename in different directories | NO |
| Hardlink path | NO |
| Directory symlink | YES |
| Case-only difference | YES |

Two read-only netsh wfp show appid queries also succeeded, confirming NT-device path-shaped output. They are not a third authenticated per-connection owner. All fixture files were removed, no optional alias cases skipped, and no copied EXE executed.

## Independent archival audit

The ZIP is preserved at research/wfp-ale/fixtures/r15-native-rust-windows.zip; verify_native_r15.py checks its exact GitHub SHA256, CRC, both source Git blob digests, Windows CRLF checkout SHA256, strict JSON schema, five scenarios and all negative release flags. The test_verify_native_r15.py suite completed **12/12 PASS** locally, including intentional tampering, false Rust execution flags, source divergence, swapped scenario outputs, kernel/release promotion and missing evidence.

Windows checkout SHA256: Python d1a4050c18f144ca5072440e5804bc685066c950dc485f46f3c643283bdd9ba9; Rust 72da2eeb6fd53f2d57e3752c663859916589a235687b5729dcf7b75d9f94b445.

Reproduce offline: python3 research/wfp-ale/verify_native_r15.py research/wfp-ale/fixtures/r15-native-rust-windows.zip research/wfp-ale

## Evidence boundary

R14 established a short 8.3 pathname component as the cause of the tested input-versus-handle AppId mismatch; GetLongPathNameW corrected the input for non-symlink fixtures but not the symlink. The R15 Rust-vs-Python check independently confirms the AppId equality decisions, not process-object identity.

Still **NO-GO**: ALE_CONNECT_REDIRECT kernel classify -> referenced EPROCESS creation epoch + canonical image -> owned redirect context -> WSAIoctl redirect records on the actual accepted proxy socket -> independently proved no-DIRECT, including IPv4/IPv6, DNS/UDP, SSH/WFP loss. NDISRD does not expose a trustworthy per-frame process owner token via its current documented buffer. G2/PacketBound remains OPEN; historical G1 dd1ab3c does not transfer; release_accepted=false.

Production transparent capture requires separately approved signed connection-aware kernel backend and all driver/VNC/SYSTEM rescue/rollback gates. Limited SOCKS-only beta is not blocked by this research and is not modified here.

Microsoft primary sources: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0 ; https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers .
