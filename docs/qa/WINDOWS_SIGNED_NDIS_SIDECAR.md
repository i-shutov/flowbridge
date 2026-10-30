# FlowBridge Windows 10/11: vendor-signed driver path

**Decision (2026-10-30).** For personal Windows 10/11 use, prefer the official Microsoft-signed Windows Packet Filter driver via separately installed ProxiFyre rather than building/signing/loading FlowBridgeWfp.sys. The current PR provides safe configuration export only; it does NOT claim transparent interception has passed native QA.

## Source and license boundaries

- Commercial Proxifier Standard v4 uses ProxifierDrv (vendor WFP), not ProxiFyre or WinDivert.
- ProxiFyre is a different, open-source AGPL-3.0 application built on Windows Packet Filter (NDISRD / ndisrd.sys). Its official online setup can install required Windows Packet Filter and Visual C++ prerequisites. Source: https://github.com/wiresock/proxifyre/blob/main/docs/installer.md
- NT KERNEL states its Microsoft-signed Windows Packet Filter is free for personal, noncommercial use; commercial redistribution is not included. Source: https://www.ntkernel.com/windows-packet-filter/download/
- This repository does not bundle vendor binaries, driver, installer, service, signing keys or credentials. The original Rust engine and Windows GUI continue to own SSH and routing. No vendor source is copied.

## First vertical: export-only sidecar

1. On an authorized Windows 10/11 test machine, obtain the matching ProxiFyre online setup from https://github.com/wiresock/proxifyre/releases and verify its release SHA-256 sidecar before elevation. Its own setup may be unsigned although the Windows Packet Filter prerequisite is signed. Do not disable Secure Boot, Memory Integrity or Windows Defender.
2. Install via vendor wizard, back up existing ProxiFyre configuration and check the actual NDISRD version/signature and device availability. Do not assume signature means runtime compatibility.
3. In FlowBridge, start managed SSH (verified host key), with SOCKS5 ingress on 127.0.0.1:1081 (or another loopback IPv4 port).
4. Select 1–64 application EXEs and click **Export ProxiFyre** in FlowBridge. It generates a configuration candidate with exact selected input paths, no catch-all, TCP-only, IPv4+IPv6, LAN bypass and carrier-process exclusions. It refuses the FlowBridge block-others option and rejects unsafe paths. It never copies SSH keys, authentication material, service tokens or credentials into the export.
5. In the vendor GUI review this candidate against its existing config. ProxiFyre reads app-config.json beside its installed ProxiFyre.exe; do not blindly overwrite existing settings. Apply and restart through the supported vendor UI.
6. Record actual selected / unselected TCP routing through app -> NDISAPI/ProxiFyre -> FlowBridge SOCKS5 -> SSH -> remote endpoint; verify normal and failure cases, Windows firewall and kernel protections, and cleanup.

## Explicit gaps

- This PR does not install/activate ProxiFyre or automatically manage its service. The integrated setup, consent, rollback and single-UI lifecycle are subsequent work.
- ProxiFyre's documented path selector uses substring matching, not exact verified process identity. The input paths in the config are normalized but actual process matching must be tested; publisher identity is not verified.
- TCP-only does NOT mean UDP/QUIC is blocked. Unsupported traffic may remain direct. This is not a kill switch.
- Packet interception observes IP addresses after name resolution. There is no guaranteed remote DNS, no full DNS leak protection, and no DoH/DoT/IPv6 leak claim. The FlowBridge remote-DNS toggle applies only to hostname-bearing explicit SOCKS requests.
- The current FlowBridge original WFP driver remains research-only and is not part of this personal release plan.
- No existing WFP driver, vendor program, kernel protection policy, firewall setting or network adapter is changed by the export.

## Required release gates

- Exact-head Windows CI compiles the exporter and passes negative tests without vendor driver installation.
- Supply-chain checks: official vendor release digest, actual Microsoft signature and NDISRD compatibility on Windows 10 and 11.
- Installer integration: guarded download/verification and explicit approval for elevated vendor installer, safe service lifecycle, rollback. Respect license boundaries; do not redistribute third-party binaries in public FlowBridge artifacts.
- Real Windows 10/11 evidence: IPv4/IPv6 selected-app SSH path, unselected bypass, process matching, no loop; failure semantics, DNS and UDP behavior documented with packet captures.
- Clean uninstall and recovery, and actual protected-mode leak tests if protected mode is advertised.

No release 1.0 or transparent native PASS is justified by export-only CI.
