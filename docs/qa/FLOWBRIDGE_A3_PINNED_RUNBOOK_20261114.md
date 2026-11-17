# Windows A3 — frozen explicit-beta candidate operator runner

Date: 2026-11-14. Scope: existing FlowBridge 0.3.0-beta.1
source f5ecd48d8f81c594f755a55e7969b57d20903020,
unified GitHub Actions run 43407093536. This does not claim
transparent routing, driver loading or FlowBridge 1.0 acceptance.

## Inputs already pinned

The original QA kit was produced in
https://github.com/i-shutov/flowbridge/actions/runs/43407093536/artifacts/14028139291
and its INNER ZIP is named
FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip.

SHA-256 of this inner ZIP:
4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8

Pinned source SHA: f5ecd48d8f81c594f755a55e7969b57d20903020.
Windows installer SHA:
74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504

**Never** compute your own expected hash from the file just downloaded;
the expected values above and in the script come from the frozen candidate
index independently inspected in the earlier B0 workflow.

## On the owner VM-910136 (Windows 10 Pro 22H2 x64)

The prepared
tools/windows/FlowBridge-ExplicitBeta-A3-Frozen.ps1
script is plain PowerShell 5.1 and requires Python 3.10+ with py.exe.
It checks the pinned kit hash and file name, rejects Windows Server,
non-Pro / pre-22H2 / non-x64 OS and unexpected hostname, and preserves
all existing user profiles. It will not install drivers or modify
firewall, Defender, SecureBoot, DNS, NDISRD or WFP filters.

Download the original verified candidate Actions artifact in a browser
and extract its INNER QA kit ZIP to a stable directory; do not alter its
contents. Save the runner script from the versioned GitHub PR #58 source.

**Phase 1 — default; no installation:**

~~~powershell
$Script = '.\tools\windows\FlowBridge-ExplicitBeta-A3-Frozen.ps1'
$Kit = 'C:\Temp\FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script -KitZip $Kit -ExpectedComputerName 'VM-910136'
~~~

The tool creates a unique folder under Documents\FlowBridge-A3 with
extracted frozen files and native-preflight/native-acceptance.json.
Its console terminal verdict should be A3_BYTES_PASS / A3_NATIVE_NOT_RUN.
This is **NOT** an owner GUI/SSH PASS.

**Phase 2 — explicitly invokes beta install/GUI/TCP/upgrade/uninstall:**

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script -KitZip $Kit -ExpectedComputerName 'VM-910136' -Execute
~~~

The operator must be in the interactive desktop, normal user account,
FlowBridge windows closed, no pre-existing beta installation (the
underlying exact-source acceptance script fails rather than removing
existing beta profiles), stable installation/data remain untouched.
The script checks the operator-runner's returned JSON and refuses
to label it full A3/release acceptance. It leaves QA evidence in its
unique directory and never purges user profiles.

After automated A3, **still required**: independent review of the
original BMPs, keyboard/GUI interaction, real managed OpenSSH host-key,
SOCKS5h DNS semantics, all-down refusal/Stop, process recovery and
Windows 11 independent targeted testing of the SAME bytes.

## CI evidence and limits

A separate PowerShell 5.1/7 workflow parses the exact script and tests
tampered-kit refusal on hosted Windows Server **without** setting
-Execute, installing beta, altering the OS or claiming owner-native PASS.
Original CI logs/artifacts must be checked for exact PR SHA.
Hosted success cannot transfer to VM-910136 user evidence.

Original protocol:
https://github.com/i-shutov/flowbridge/blob/5dd6ca35d975e536cd8901ebd9cae158aef02797/docs/qa/EXPLICIT_BETA_NATIVE_ACCEPTANCE.md

No release publication, token, signing keys, drivers, user secrets
or system changes should be made based on a check-only result.
