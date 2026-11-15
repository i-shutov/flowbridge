# WIN-01/R1: Read-only provenance of a separately installed signed NDISRD driver

Date: 2026-11-15. Windows-first product target Windows 10 Pro 22H2 x64 + Windows 11 Pro x64.
**This is a R1 preparatory provenance tool, not G2 packet ownership acceptance.**

## Contract and source

Draft feature branch is stacked on `integration/windows-rust-capture-agent-20261031`,
which already implements read-only NDISRD device version, adapter inventory
and lab-only (not protected) packet I/O in Rust. This script does not embed
vendor code/driver, start services, install NDISRD, change driver modes,
invoke WFP/BFE, mutate Defender/firewall/BCD, or access external networks.

Tool: `tools/windows/FlowBridge-NDISRD-DriverProvenance-ReadOnly.ps1`.

Default WinPowerShell 5.1 behavior: inspect service registry
`HKLM:\SYSTEM\CurrentControlSet\Services\NDISRD`, query local SCM
status read-only, resolve **only an ordinary canonical local .sys image**
(`\SystemRoot`, `%SystemRoot%`, `System32`, or fully qualified DOS path),
hash the bounded non-reparse-point file with SHA256, read
`Get-AuthenticodeSignature`, record the observed signing status and signer
subject, and output one JSON file. Raw credentials, packet bytes and foreign
service configuration are never saved. If unavailable, return an explicit
NO_LOCAL_DRIVER/DRIVER_IMAGE_UNVERIFIED outcome — never invent a green gate.

## Read-only owner Win10/11 command

```powershell
$script = '.\tools\windows\FlowBridge-NDISRD-DriverProvenance-ReadOnly.ps1'
$out = Join-Path $env:USERPROFILE 'Documents\FlowBridge-NDISRD-ReadOnly.json'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -OutputPath $out -ExpectedComputerName 'VM-910136'
```

`-ExpectedComputerName` is a verification guard, not a target hostname
discovery or remote connection. For another Win11 machine pass its actual
expected hostname. The script only runs locally. Do not install an NDISRD
driver merely to obtain a positive report; independent vendor/terms
review and a dedicated rollback-capable test lab are prerequisites.

## Hosted positive and negative checks

The GitHub-hosted `windows-2025` workflow `windows-ndisrd-provenance-readonly.yml`
runs the actual script twice: against the real `NDISRD` service, which can
legitimately be **absent**, and against Windows' installed **TCPIP** kernel
driver using a CI-only `-HostedSystemDriverControl` flag. This verifies the
real Windows registry, path, file SHA256 and Authenticode code path without
asserting TCPIP as NDISRD or loading anything. It also checks wrong-host
refusal, rejects six hostile path formats, and statically rejects
mutating service/network commands in PowerShell AST.

**Cryptographic trust distinction:** a successful Authenticode status of a
file on disk does not prove it matches the currently loaded NDISRD image,
does not establish vendor licensing or an independently pinned hash, and
does not substitute for Microsoft kernel-mode code integrity/certificate
chain acceptance. A file's hash/status and the driver's running state
must not be used as packet-origin authority. `Get-AuthenticodeSignature`
may observe a catalog or embedded signature; signer-specific driver
qualification is still an independent task.

## What remains mandatory for G2

Official NDISRD `INTERMEDIATE_BUFFER` exposes a bounded Ethernet packet,
direction and NDIS flags. It does **not** furnish a signed/OS kernel
process-creation epoch or connection ID per packet. IP Helper/ETW
tuple/time guesses do not bridge that trust boundary. Consequently even
a genuine vendor-signed and running NDISRD can never automatically set
`owner_process_per_packet_proven=true` or `native_g2_accepted=true`.

The tool's JSON therefore *always* emits `native_g2_accepted=false`,
`release_1_0_accepted=false`, `kernel_connection_id_available=false`,
`microsoft_kernel_code_integrity_policy_verified=false`,
`on_disk_file_proves_currently_loaded_image=false`, and
`file_hash_independently_vendor_pinned=false`.

Approved product backend remains **NDISRD-only** per issue #41.
Switching to WFP/ALE or another connection-aware signed driver needs
separate explicit owner authorization, physical Win10+Win11 evidence
and rollback. No G2 exit criterion is weakened.

Primary API references:

- NDISRD [ReadPacket / INTERMEDIATE_BUFFER fields](https://www.ntkernel.com/docs/windows-packet-filter-documentation/c-api/readpacket/)
- Windows [QueryServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw)
- Windows [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)

**Acceptance:** read-only R1 file provenance can pass as a narrow preparatory
subgate; the 10 Windows 1.0 release gates all remain unaccepted.
