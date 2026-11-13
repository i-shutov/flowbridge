FlowBridge Explicit SOCKS Candidate — Windows x64
================================================

ENGINEERING CANDIDATE, NOT A PRODUCTION RELEASE
Candidate version: 0.3.0-beta.1, explicit SOCKS-only engineering build.

Supported: local SOCKS5/SOCKS5h TCP listener, explicitly configured clients,
external upstream proxies, user-owned OpenSSH -D with watchdog (GUI),
strict host-key checking and local policy/metrics.

NOT SUPPORTED: transparent interception of arbitrary EXEs, WFP/NDISRD
driver installation, system proxy/DNS replacement, system kill switch,
UDP/QUIC proxying, global DNS leak protection, process-specific routing
without a verified native capture backend, and preserving in-flight TCP
connections after losing their SSH channel.

The "Applications" discovery list is informational only in this build.
Native interception and system rule export buttons are disabled.
To use: configure the application/client explicitly with
SOCKS5h 127.0.0.1:1081, after pressing Connect inside FlowBridge.
SOCKS5h delegates hostname resolution for that request to the proxy;
applications doing their own DNS/DoH before connecting remain outside
the stated protection boundary. Unconfigured apps access the OS network.

OpenSSH: provide server, account, key/agent and known_hosts under
the Connection tab. Unknown or changed server host keys must be
independently verified and explicitly trusted. No password/secret is
stored by this beta installer; never disable StrictHostKeyChecking.
This build does not install or start the Windows OpenSSH server.

The install is PER USER into the separate "FlowBridge Explicit Beta"
directory and registry namespace. The profile is stored separately at
%LOCALAPPDATA%\FlowBridgeExplicitBeta\profile.json.
The uninstaller removes known application binaries, shortcuts and the
per-user install registration. It PRESERVES profile and user-created files.

Signed installer: NO. Approved release: NO.
No Windows kernel driver, helper or network interception service included.
Do not elevate installer for driver work: this candidate never does it.

Project and updates: https://github.com/i-shutov/flowbridge

BUILD-METADATA.json identifies the exact clean source commit and Cargo.lock.
SBOM.cdx.json inventories resolved production/build inputs for this target.
licenses/THIRD_PARTY_NOTICES.txt contains the actual corresponding license texts.
This inventory does not certify binary linkage, security or independent license review.
