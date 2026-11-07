# R14 — real Windows AppId path mismatch: 8.3 component verified

Date: 2026-11-07. Independent, read-only WFP/ALE R&D ONLY on
`research/windows-wfp-ale-attribution-20261107`. This **does not** modify
`main`, release, beta branch `integration/windows-rust-capture-agent-20261031`
or PR #56. No driver, callout, NDISRD, WFP filter, network, service, UFW,
firewall, Defender, VNC, SecureBoot, MemoryIntegrity, runner or automation
changes. All test payloads were local temporary copies of system `where.exe`,
never executed. One standard hosted Windows-2025 job, no custom runners.

## Authentic native evidence (not a synthetic kernel owner)

| Provenance | Exact pinned value |
|---|---|
| Research source executed | `4562aad02b1eac48f8dd87783527534a2806373c` |
| Actual GitHub Actions run | 42366194426, `SUCCESS` |
| Windows-2025 hosted job | 128384679860, `SUCCESS` |
| Artifact | 13572085662, `FlowBridge-R14-AppId-namespace-42366194426` |
| Original GitHub artifact SHA256 | `8e58b08abf79fc70bfea5c8dbf7046bc5719dc43ebf85c9b5450b676e3e87d40` |
| Python source Git blob | `e7a25523868241efa71a649b9528908b1cba1033` |
| Windows checkout source SHA256 | `4ef5d70115b672f615ecf418572b243390cd4a97fb808f43c6e98e6a8ecbbb3e` |
| Source fingerprint explanation | Windows checkout CRLF transformation exactly reproduces SHA256 |

The actual ZIP and the R14 original source are both retained in this branch.
`verify_native_r14.py` checks GitHub ZIP digest, CRC, source Git blob,
CRLF-derived SHA256, strict no-PII JSON schema, real 5-case outcomes and
negative security flags. No binary is executed by this verifier.

## R12 discrepancy: decisive 8.3 mechanism

Native user-mode Windows queries:

1. `FwpmGetAppIdFromFileName0` on the supplied DOS path of a temporary fixture;
2. `QueryDosDeviceW` on the fixture's local drive; append the supplied pathname
   to get a *lexical* NT-device representation (diagnostic only);
3. `GetLongPathNameW` on the same DOS path; obtain another WFP AppId;
4. `GetFinalPathNameByHandleW(VOLUME_NAME_DOS/VOLUME_NAME_NT)` on an opened
   file handle, and look up the handle-resolved DOS path with WFP;
5. `GetFileInformationByHandle` on both file handles; compare volume serial
   and file-index **privately**, emitting only equality. This is file identity
   on the hosted local volume, not EPROCESS or connection identity.

In every *non-symlink* case, the supplied AppId **exactly matched** the
`QueryDosDeviceW` *lexical* device path; it **did not match** the handle-derived
AppId. The path mismatch contained exactly **one component** with an 8.3
`~n`-style short-name marker. `GetLongPathNameW` changed that spelling, and
its WFP AppId **then exactly matched** both the handle-derived WFP AppId and
the `VOLUME_NAME_NT` path. This is concrete Windows-2025 native evidence that
**the tested source of the R12 input-vs-handle mismatch was a short 8.3 path
component**. No raw path, AppId, user name or NT volume identifier was
recorded, so no broader claim about untested installations or filesystems.

The symlink case is an important counterexample to an overbroad fix:
`GetLongPathNameW` expanded short names, but its WFP AppId still differed from
the handle-resolved AppId; the original and expanded AppIds were equal, while
`GetFinalPathNameByHandleW` resolved the target. Thus **long-name expansion
alone is not a universally sufficient canonicalization procedure**. Tests
must preserve aliases, reparse points and the exact WFP AppId emitted by the
kernel for the classified connection. Filename equality is not kernel-owner
attestation.

## Physical file equality is not WFP AppId equality

| Fixture pair | `GetFileInformationByHandle`: same file ID? | Input WFP AppId equal? |
|---|---:|---:|
| Same path read twice | YES | YES |
| Two byte-identical `probe.exe` in separate directories | NO | NO |
| NTFS hardlink to the same file under a different name | **YES** | **NO** |
| Directory symlink to the same file | YES | YES |
| Path differing only by letter case | YES | YES |

This **falsifies** treating the WFP AppId as a content hash or immutable file
object identifier. The observations concern local Windows Server 2025 only.

## Quality assurance and exact code changes

- New `appid_namespace_r14.py`: read-only API calls, local fixture matrix,
  8.3 expansion/NT-device comparisons, file-ID comparison and bounded,
  sanitized booleans only. Never starts a copied EXE.
- New `test_appid_namespace_r14.py`: 17 independent offline tests, including
  mock 8.3 path, unicode/structure, hardlink-identity negative, mismatched
  AppId, restricted consent and no-driver API surface; local **17/17 PASS**;
  hosted Windows test step also PASS.
- New `.github/workflows/research-wfp-appid-namespace-r14.yml`: restricted
  one-shot `push` trigger for **its exact workflow path only**, research
  branch only, GitHub-hosted standard `windows-2025`, 10-minute job limit,
  no persistent checkout credentials, no signing or drivers. Native job and
  independent result-scoping verification both PASS.
- New `verify_native_r14.py` and `test_verify_native_r14.py`: retained exact
  artifact reader, 16/16 independent adversarial tests PASS, detects forged
  PASS flags, missing/changed aliases, hardlink identity spoofing, changed
  source SHA and false symlink/8.3 generalizations. Python syntax PASS.
- The pinned sanitized ZIP has SHA256 exactly matching GitHub API. The
  redacted output JSON is machine-readable and contains no filesystem path,
  AppId, PID, executable contents or credential.

Run offline independently:

```sh
python3 research/wfp-ale/verify_native_r14.py \
  research/wfp-ale/fixtures/r14-native-windows.zip \
  research/wfp-ale/appid_namespace_r14.py
python3 -m unittest discover -s research/wfp-ale -p test_verify_native_r14.py -v
```

## Trust boundary: what remains impossible to claim

R14 proves **user-mode WFP AppId behavior**, not `FWPS_LAYER_ALE_CONNECT_REDIRECT`
per-connection identity, not a `FWPS_METADATA_FIELD_PROCESS_ID` tied to a
referenced `EPROCESS` creation epoch, not kernel-origin ALE redirect context
or records on the *actual accepted* socket, and not OS-enforced direct denial
under SSH/WFP loss. Neither an old NDISRD packet buffer nor IP Helper / ETW
5-tuple snapshots receives a trusted packet-owner token from this test.
NDISRD PacketBound / G2, protected transparent routing and system no-DIRECT
remain **OPEN/NO-GO**. No reuse of historical G1 from `dd1ab3c`; beta approval
must be a separate scope with its own QA gates. `release_accepted=false`.

**Decisive next experiment:** independent cross-platform reproduction of
`GetLongPathNameW` / handle-path WFP AppId normalization on real Windows
10/11 x64. Separately, genuine `ALE_CONNECT_REDIRECT → pinned EPROCESS →
context → accepted-socket record` authority requires a licensed/approved
signed connection-aware backend, explicit owner authorization and every
VNC/SYSTEM rescue/rollback/safety gate. No amount of additional read-only
user-mode 5-tuple/AppId correlation can establish that missing kernel proof.

### Official Microsoft API contracts

- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getlongpathnamew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers
