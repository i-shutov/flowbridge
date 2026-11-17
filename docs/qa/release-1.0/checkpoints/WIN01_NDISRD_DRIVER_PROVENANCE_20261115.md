# WIN-01/R1 — NDISRD installed-driver provenance, Windows-first checkpoint

Date: **15 November 2026**. Status: **HOSTED READ-ONLY PRE-FLIGHT PASS; OWNER NDISRD R1 NOT_RUN; G2 NO-GO**.

## What changed in actual source

Draft [PR #68](https://github.com/i-shutov/flowbridge/pull/68) is based on
`integration/windows-rust-capture-agent-20261031` rather than `main`,
because the authorized clean-room Rust NDISRD code lives there.
Exact tested PR source: `5528fb5962fcb6e1bd008d2f42debef6dd95f967`.

1. `tools/windows/FlowBridge-NDISRD-DriverProvenance-ReadOnly.ps1` reads the
   separately installed NDISRD service registration, type/status, an ordinary
   bounded local `.sys` file, its SHA256 and observed Windows Authenticode
   status. A provided external SHA reference can be compared; mismatch and
   malformed pins are denied, but a self-supplied pin is never interpreted
   as independently verified vendor provenance.
2. New product Rust `crates/flowbridge-capture/src/windows_ndisrd_image.rs`
   queries the actual local Windows SCM via **QueryServiceConfigW**, with an
   8 KiB aligned buffer, checked returned pointers, UTF-16 decoding and
   bounded service-path classification. The status is exposed through
   `windows_ndisrd_service::report()` and the existing diagnostic path;
   no new DLL, driver or network configuration is added.
3. Real Windows positive and negative tests inspect a known installed
   Microsoft TCPIP service/driver and independently exercise NDISRD absence,
   six hostile service-path forms, an incorrect hostname, explicit SHA
   match/mismatch and a malformed SHA. Read-only command AST checks prohibit
   mutable service, registry, WFP, firewall and code-integrity operations.
4. Portable Rust tests still run on Windows, Linux and macOS. The Windows
   SCM reader is OS-conditional and the shared Rust policy/transport remains
   platform-neutral.

## Original CI evidence

| Check | Exact result |
| --- | --- |
| [Windows NDISRD provenance #43706911211](https://github.com/i-shutov/flowbridge/actions/runs/43706911211) | **1/1 SUCCESS**. Native PowerShell 5.1/7, real SCM/file path, Authenticode, hostile path and reference-pin negatives |
| [Original ZIP evidence #14159275280](https://github.com/i-shutov/flowbridge/actions/runs/43706911211/artifacts/14159275280) | SHA256 `18ade9427ae8b18e26f15d3b4c1f541988b89706f7f7d8282c2703357496bf59`, ZIP CRC PASS, 6 original JSON files |
| Actual NDISRD on **hosted Windows Server 2025** | **NOT_INSTALLED**; no product NDISRD packet/driver origin claimed |
| Positive system driver control, not NDISRD | Windows `Tcpip` `.sys` image SHA256 `a160eb06c856a9cd392df50782df2c21564f7c8a4dda4eeb0a79aca0e7aa23bf`, Authenticode `Valid` |
| Same-driver reference-pin negative | Good reference matches but `supplied_vendor_reference_authority_verified=false`; wrong hash and malformed input denied |
| [General native and Rust #43706911213](https://github.com/i-shutov/flowbridge/actions/runs/43706911213) | **5/5 SUCCESS** on Windows, Linux and macOS, including Windows native app and NDISRD read-only SCM source |
| [Full capture integration #43706911217](https://github.com/i-shutov/flowbridge/actions/runs/43706911217) | Dedicated **G2 job FAILURE** remains. `G2_PACKET_BOUND=UNPROVED`. No reclassification of required failure as PASS |

All six original native reports were extracted from the downloaded artifact;
each has `native_g2_accepted=false`, `release_1_0_accepted=false` and
`microsoft_kernel_code_integrity_policy_verified=false`. A `Valid`
Authenticode result on the **on-disk** TCPIP control file cannot prove
vendor rights, currently loaded image identity, kernel code-integrity
acceptance, or NDISRD origin for selected packets.

## Owner-target read-only command (no driver load)

On the dedicated Win10 Pro machine, using the pinned branch's script:

```powershell
$script = '.\tools\windows\FlowBridge-NDISRD-DriverProvenance-ReadOnly.ps1'
$out = Join-Path $env:USERPROFILE 'Documents\FlowBridge-NDISRD-ReadOnly.json'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -OutputPath $out -ExpectedComputerName 'VM-910136'
```

Do not supply the TCPIP control image SHA as if it were a vendor NDISRD
reference. For a genuine NDISRD binary, use an independent official
vendor-published SHA / supply-chain record and rerun with
`-ExpectedVendorSha256 <independent vendor hash>`.
Repeat separately on a Windows 11 Pro x64 lab with its exact hostname.
Save original JSON and file SHA; no drive, service, filter or firewall
modification is requested by this preflight.

## Windows G2: why the blocker is not closed

Official NDISRD [ReadPacket](https://www.ntkernel.com/docs/windows-packet-filter-documentation/c-api/readpacket/)
returns the Ethernet frame, length, NDIS flags and direction in
`INTERMEDIATE_BUFFER`; there is no trustworthy per-packet kernel process
incarnation/connection ID in this existing ABI. Independent
`QueryServiceConfigW`/Authenticode checks prove neither packet origin
nor no-DIRECT for selected EXEs. IP Helper/ETW time/5-tuple correlation
cannot be silently promoted to `PacketBound`. Windows G2 read-only ETW
native CI remains **FAIL**.

**Required next decision:** the existing authorization is NDISRD-only
(Issue [#41](https://github.com/i-shutov/flowbridge/issues/41)).
Actual protected Windows 1.0 requires a driver/backend providing genuine
connection→AppId/PID epoch/original destination with a signed kernel
provenance/redirect receipt. A WFP ALE redirect backend is an
architectural candidate, **not** an approved product switch.
Before using it the owner must explicitly authorize the architecture,
driver signing/license and isolated Win10/Win11 lab rollback/rescue.
No driver installation or WFP conversion was performed here.

All Windows `WIN-00…09` release gates remain `accepted=false`;
original project `R01` remains NO-GO. This is a narrow, real
engineering preflight, **not a 1.0 release acceptance**.

Machine-readable source/CI registry:
[WIN01_NDISRD_DRIVER_PROVENANCE_20261115.json](WIN01_NDISRD_DRIVER_PROVENANCE_20261115.json).
