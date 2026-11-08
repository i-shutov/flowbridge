# R39-DEV — disposable Windows 11 Hyper-V laboratory

Status: SOURCE TOOLING ONLY. VM not deployed, test signature not produced,
driver not loaded, R39 native E2E not verified, G2 NO-GO. This isolated branch
does not modify main, beta PR #56 or the independent WFP/ALE research branch.

## Hardware and safety requirements

Official Windows 11 VM minimum: Generation 2, 2 vCPU, 4 GB RAM,
64 GB VHDX, UEFI Secure Boot and vTPM. The previous Windows Server VPS
(4 GB RAM) cannot host the Windows 11 guest alongside the server.

Conservative host preflight: guest RAM plus 8 GB physical host RAM,
guest RAM plus 2 GB currently free, 4 logical processors, and guest VHDX
size plus 24 GB free disk. Recommend separate Hyper-V-capable host with
16 GB RAM, 4+ logical CPU threads and 120 GB+ free SSD space.
Hyper-V role must already be installed. Nested virtualization on virtual
providers must be enabled by the OUTER host/provider; Get-VMHost alone is
not sufficient evidence that a nested VM will successfully start.

Host scripts never install Hyper-V, reboot the host, change host BCD,
firewall, production NICs, Secure Boot or Windows driver policy. No default
network switch is attached to the guest. Failures leave inspectable state;
no automatic deletion or restoration of unrelated host assets.

## H0 — audit actual host (read-only)

PowerShell 7, Administrator, on the proposed HYPER-V HOST (not inside W11).
Supply an authentic official Windows 11 x64 ISO. Prefer 25H2 for initial
driver catalog work because WDK Inf2Cat currently documents 10_25H2_X64,
not a 26H2 catalog identifier. The Microsoft 26H2 Enterprise eval ISO is
available for a 90-day evaluation, but its Inf2Cat compatibility needs a
separate explicit check. The official published 26H2 English US eval ISO
SHA256 is BC3F24086EBADC94489066B5AD78089E2CF5C3491E90E790BB81A2B199C10E38.

~~~powershell
$lab = 'research/wfp-ale/lab-win11'
& "$lab/host-preflight.ps1" -VMRoot 'D:\FlowBridgeLab' -IsoPath 'D:\ISO\Win11_25H2_x64.iso' -OutputPath 'D:\FlowBridgeLab\H0-audit.json'
~~~

If ready_to_create=false, STOP. This preflight is not proof of nested
virtualization on a provider VPS or of a working rescue connection.

## H1 — create new Gen2 VM, guest Secure Boot ON, no network

~~~powershell
& "$lab/new-labvm.ps1" -VMRoot 'D:\FlowBridgeLab' -IsoPath 'D:\ISO\Win11_25H2_x64.iso' -Apply -OutputPath 'D:\FlowBridgeLab\H1-result.json'
~~~

Creates only a NEW FlowBridge-R39-DEV-W11 Gen2 VM with 96 GB dynamic
VHDX, 6 GB RAM, 2 vCPU, vTPM and a connected official ISO. VM remains
OFF and disconnected. The tool refuses to modify an existing VM.

## H2 — manual installation using Hyper-V console

Boot using VMConnect, install Windows 11 normally with vTPM and Secure
Boot ON. Respect Microsoft license/evaluation requirements; no CPU, TPM
or online-account bypass. Name the Windows 11 guest FB-R39-DEV, verify
guest BitLocker/recovery state, demonstrate console access, then shut it
down completely.

## H3 — snapshot clean guest, change ONLY guest firmware

~~~powershell
& "$lab/prepare-vm-testmode.ps1" -VMName 'FlowBridge-R39-DEV-W11' -Apply -ConfirmWindowsInstalled -ConfirmGuestBitLockerRecoverySafe -OutputPath 'D:\FlowBridgeLab\H3-result.json'
~~~

Requires the dedicated VM to be OFF. Creates a Standard checkpoint and
only then disables that VM's Secure Boot (HOST stays untouched). Guest
BCD is unchanged. TESTSIGNING is not a production release environment.

## G1 — guest TESTSIGNING after boot, then guest reboot

Copy scripts into guest C:\FlowBridgeLab\lab-win11; elevate PowerShell 7
INSIDE Windows 11, never on the Hyper-V host.

~~~powershell
$lab='C:\FlowBridgeLab\lab-win11'
& "$lab/guest-testmode.ps1" -Apply -ExpectedComputerName 'FB-R39-DEV' -OutputPath 'C:\FlowBridgeLab\G1.json'
Restart-Computer
~~~

Guest testmode script validates Windows 11 + Hyper-V virtual hardware,
exact FB-R39-* name, admin role, Secure Boot OFF and BitLocker protection
OFF. After guest reboot independently verify BCDEdit and Test Mode.

## G2 — exact-source local SYS/CAT test signing (no driver load)

Supply original unsigned SYS and INF from verified no-load
Actions 42465140005, artifact 13611128671, exact source
c2829e87da59e16f06b631af683aee4101ff6621.
Expected SYS SHA256:
c613fd1d98a9a4e22d6551f07143c7821263df2732c3e25bae2543b1ca7d4c00
Expected INF SHA256:
29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd

Inside guest, install official WDK Inf2Cat and SDK SignTool.
Use the exact signed-candidate gate with explicit guest machine name:

~~~powershell
& "$lab/sign-lab-driver.ps1" -UnsignedSys 'C:\FlowBridgeLab\unsigned\flowbridge_g2_witness.sys' -UnsignedInf 'C:\FlowBridgeLab\unsigned\flowbridge_g2_r38.inf' -Inf2CatOS 10_25H2_X64 -ExpectedComputerName 'FB-R39-DEV' -Apply -OutputPath 'C:\FlowBridgeLab\G2.json'
~~~

Original SHA256 must match. The private test certificate key is created
non-exportable in the GUEST only, public certificate is trusted in guest
stores only, output is a separate signed staged SYS/CAT. It does NOT load,
install or register a kernel driver or change BFE, WFP or services.
Authenticode verification is NOT proof that kernel signing policy
allows this driver in normal Windows with Secure Boot.

## G3 — native driver load and physical R39 acceptance: NOT YET ADMITTED

Before any driver load or WFP activation, independently verify VMConnect
and emergency VNC, SYSTEM rescue, real rollback checkpoint and separate
physical packet observation. Then one unmodified EXE must complete an
actual ALE_CONNECT_REDIRECT → AUTH → socket context/records → CLAIM →
SSH pinned host+user authentication → exact remote target response.
Test siblings, PID reuse, R41/R42 post-CLAIM owner-exit, IPv4/IPv6,
DNS/UDP/QUIC, lease loss, BFE crash, and physical DIRECT absence.
No unit-model or test-signed binary can substitute for G3 evidence.

## Microsoft sources

- https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements
- https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization
- https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/checkpoints
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/test-signing
- https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/inf2cat
- https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
- https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file

Truth: lab_vm_created=false; test_signature_produced=false;
driver_loaded=false; native_ale_e2e=false; g2_pass=false;
release_accepted=false until independently executed and verified.
