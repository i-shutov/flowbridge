# R19 owner authorization — 2026-11-07

The owner explicitly authorized creating/installing a new kernel backend and push-trigger execution in the current conversation. This supersedes those two prior prohibitions only. The research branch remains isolated from beta PR #56, main/release, other repositories, services, runner labels and automation settings.

R19 creates an original Rust WDM observer backend and a scoped push CI build, not a production redirect implementation. It uses process creation callbacks to hold the original EPROCESS and executable FILE_OBJECT, rejecting unknown/pre-existing/terminated/reused PIDs and bounded storage overflow. A selected exact ALE AppId must match the captured creation path. No current-thread PID, late OpenProcess/PsLookupProcessByProcessId, or tuple correlation is used. All pointers stay private to the driver.

The driver registers IPv4/IPv6 ALE callouts and exposes a read-only, SYSTEM/admin-secured device IOCTL. It inserts no BFE filters, does not rewrite traffic and does not assert no-DIRECT. It captures only process instances born after callback registration, holds bounded refs until unload, and is a research candidate with unverified native lifecycle/IRQL/unload behavior.

CI compiles an UNSIGNED .sys using Microsoft's WDK headers and imports. The build job NEVER installs, signs, loads or tests the driver. No certificates, test-signing, SecureBoot/MemoryIntegrity/Defender changes, service start or WFP filters. Driver loading still requires an acceptable kernel signature, real fresh VNC proof, independent SYSTEM rescue, exact SHA, firewall/Defender and rollback gates. These gates are not present in this build-only job. Successful compilation is not G2 acceptance.

An independent job compiles the existing R17 user-mode Rust collector and attempts read-only local socket observations. It does not load the new driver and its results cannot establish original-process attribution or PacketBound. A failed test stops; the original failed run is not rerun.
