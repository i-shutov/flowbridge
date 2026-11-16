# A3 owner Windows 10 original evidence review — 2026-11-16

## Result and provenance

**Status: `EVIDENCE_STRUCTURE_PASS_MANUAL_GUI_SSH_OPEN`.**

The owner supplied a self-contained six-file ZIP for the frozen `0.3.0-beta.1` Windows 10 operator A3 test. An independent, offline, read-only audit of the original archive, its `native-acceptance.json` and five original BMPs found no CRC, schema, hash, content-uniqueness, or image-decode failure.

| Pinned property | Observed |
|---|---|
| Frozen binary source commit | `f5ecd48d8f81c594f755a55e7969b57d20903020` |
| Original candidate workflow | `43407093536` |
| User-supplied ZIP compressed size | 160123 bytes |
| User-supplied ZIP SHA-256 | `20a3596d09cab6a561463c0e14fd4cf1843b7eccd1d0ec21cf70bdb91eb402b1` |
| Original JSON SHA-256 | `5100736117c4d1ed609df062f9297ba6163d302efb9245bc79c01a75bf3c1bf8` |
| Original report status | `OWNER_NATIVE_AUTOMATED_CHECKS_PASS` |
| Original preflight status | `PINNED_BYTES_PASS` |
| Original report host basis | `operator_supplied_not_attested` |
| All six A3 phases | `install/payload/launch/upgrade/uninstall/stable_preserved = PASS` |
| BMP screenshots | 5 unique, valid 964×641 RGB, all hashes matched original JSON |
| Original safety flags | `cleanup_required=false`, `python_required=false`, `driver_loaded=false`, `system_dns_changed=false` |

The exact five BMP SHA-256 hashes (Dashboard, SSH, Proxy, Applications, Advanced) are, in this order:

- `ebab9fbe9b5187ace24690ee86c9f3f34c5b36b687060f541d6b301afc282489`
- `017baed22fd50d5106c83050a2290859fd52134039c4c0b23edbf73a5fd6d680`
- `a379bf66e46bd52eea0633e65380eb3cae87eecfb4208d5f210fbf9bd0834fd2`
- `da10deec43eef4a60f3c5c675aab7a00edf01687c1c7bfe01a073612f2ae8b6c`
- `3641228f1a1b3c76076ff05fd0180e85df28ba2a9ec4aaaf536c0208b51dfcea`

## Human visual inspection

Five distinct rendered native GUI states appear, with legible primary controls and no obvious overlapping widgets at the captured size. The dashboard reports not connected; SSH and external proxy configuration are visible; Applications explicitly says native WFP interception is unavailable; Advanced exposes JSON and recent event panes. These are static screenshots, not an actual live traffic demonstration or manual GUI/keyboard acceptance.

## Strict acceptance boundaries

The same original owner report intentionally retains `a3_full_acceptance=false`, `wfp_g2_accepted=false`, `transparent_interception_accepted=false`, and `release_accepted=false`. Offline verification of the transferred ZIP proves only internal integrity and consistency with the claimed owner-run test results, **not** independent cryptographic attestation of the Windows host, actual rerun of the frozen installer, real managed SSH host-key/SOCKS5h behavior, DNS no-leak, all-down, manual keyboard/UX, or Win11/macOS 1.0 testing.

**A3 automatic phase:** `OWNER_REPORTED_6_OF_6_EVIDENCE_VERIFIED`.

**A3 full acceptance:** `OPEN_MANUAL_GUI_SSH`.

**G2 / 1.0:** `NO_GO`.

Private original screenshots and original ZIP are retained only in the user's handoff, not committed to this public repository. This checkpoint contains non-secret artifact hashes and engineering decisions only. No WFP driver load, system policy change, merge, tag, or release is implied.

## Next acceptance step

Preserve the frozen binary identity. Run separate interactive Win10 GUI/keyboard and managed SSH host-key + SOCKS5h + disconnect/Stop + DNS-scope tests, recording manual evidence. Then consider an independent A3 release reviewer decision. Keep G2 and macOS NE acceptance separate.
