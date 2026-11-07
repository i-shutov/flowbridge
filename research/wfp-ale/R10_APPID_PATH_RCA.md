# R10: real WFP event AppId RCA and handle-resolved path probe

2026-11-07. Exclusive branch: research/windows-wfp-ale-attribution-20261107.
Parent HEAD 0e7262de074b0663c8ad4e9d4db1f4bd811bc123. No beta/PR #56/main,
workflow, runner, service, driver, filter, security or automation changes.

## Real historical Windows evidence: verified negative finding

R9 downloaded official GitHub Actions artifact 13560942739 from run 42339966586,
Windows job 128305303067, PR SHA c339df2e4d20edf1d11d45786581a68451a71929,
test-merge ab6ed5273db6e9741915a96c74809433af125870. Archive SHA256
95560460776b802da5ccd1a608495609715144a59a7fac5fbfaed331542faa92
matches GitHub artifact metadata; nested ZIP, PE64 binary, manifest and
source checks were independently verified. This is HISTORICAL evidence.

The exact Rust source (windows_wfp_dynamic_lab.rs, Git blob
a219b8c564b4e4bcdfe8e9616afc88228433efca) enumerates
FWPM_NET_EVENT_TYPE_CLASSIFY_DROP and requires the SAME live QA filterId,
remote port and TCP protocol before comparing header.appId. The original
read-only event report contains exactly THREE matching filter events;
all three have valid UTF-16 AppId and none lack AppId. Aggregate event
comparison counts: selected supplied-path AppId 0, different copied
EXE supplied-path AppId 0, selected file-handle DOS path-derived AppId 1,
different EXE file-handle DOS path-derived AppId 1, matching NT device
paths 1 each, independent Python supplied-path AppId 1.
The selected and different-copy basenames each matched only at basename
level for one event, not at supplied-path AppId bytes.

The same historical disposable QA reported selected-app denied,
unselected sibling and Python allowed, and subsequent recovery.
The historical driver-free identity query itself created no filters,
but the surrounding historical test DID create transient BFE filters.
R10 did not recreate any of them.

**Result:** WFP did distinguish two byte-identical EXEs with different
paths in an earlier hosted Windows test. AppId computed from raw input
pathname disagreed with the file-handle-resolved path AppId that agreed
with aggregate observed WFP events. Strong evidence of a PATH
SPELLING / CANONICALIZATION discrepancy; its exact causal explanation
is not yet determined. Aggregate counters are NOT per-event proof of
which source process emitted which event, much less PID+creation epoch.
The old test used different BASENAMES in one directory; same-basename
two-directory, hardlink, symlink, case and reparse scenarios are UNTESTED.

## Functional R10 change

- appid_event_correlation.py: exact-source provenance-checked archive
  auditor that preserves those negative findings and rejects forged
  event totals, incorrect live filter proof, faked APP-ID matches,
  unsafe promotions to packet owner or release, and incoherent controls.
  R9 audit_archived_appid.py is the pinned dependency.
- handle_appid_probe.py: new no-driver, read-only Windows user-mode
  experiment. For controlled duplicate EXE file content, obtains
  GetFinalPathNameByHandleW VOLUME_NAME_DOS and VOLUME_NAME_NT using
  the *actual opened file handle*, then calls the existing
  FwpmGetAppIdFromFileName0 ctypes reader on both original and
  handle-resolved DOS spellings. It compares the results, including
  native UTF-16LE device pathname, using redacted booleans only.
  Requires explicit WFP_APPID_READONLY consent. Does not execute
  copied EXEs, create a WFP filter, change any protection or network.
  Handle-resolved names are NOT guaranteed immutable file identity.
- Independent regressions in test_appid_event_correlation.py and
  test_handle_appid_probe.py; exact historical evidence analysis is
  pinned to archive digest and test-merge SHA.

## Verification and precise blocker

Locally with the original historical artifact and the exact R8/R9
dependents: 68/68 offline Python tests PASS across 5 test modules;
17 R10-specific tests PASS; syntax compilation PASS. The authentic
archived Windows data audit returned PASS with both negative AppId
spelling flags retained. Published R10 source blobs are checked against
those locally tested bytes before commit.

No new R10 Windows-native API call was executed. The available GitHub
integration supports repo write and Actions READ, not workflow_dispatch.
No Windows shell/exec tool is connected. Do not bypass via push-trigger,
issue-trigger, repeated failed workflows, paid browser, secrets, agents,
driver or WFP filter. A Windows execution channel remains BLOCKED.

When one is already authorized and available, run from research/wfp-ale:
python handle_appid_probe.py --consent WFP_APPID_READONLY
and independently validate source fingerprint, nonzero exit and
temporary cleanup. This can resolve pathname mismatches only; no
automatically derived PacketBound, kernel flow->EPROCESS, no-DIRECT,
dual-stack DNS/UDP proof or beta release gate is permitted.
G2 remains OPEN / NO-GO. Historical G1 10/10 remains ONLY dd1ab3c.
SOCKS-only beta scope is independent and must not wait for R10.

Primary Windows API sources:
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_classify_drop0
https://learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers-
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
