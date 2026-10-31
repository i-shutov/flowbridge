# Actual Windows OpenSSH load — isolated hosted acceptance

This executable QA track is separate from Windows WFP driver testing. It must
not be counted as proof of the user's Windows 10/11 exact executable, loaded
kernel capture, per-app DNS, or a signed public 1.0.

`windows-real-ssh.yml` runs only on disposable Windows-2025. It selects the
SYSTEM Windows OpenSSH client by its exact System32 path, verifies Microsoft
Authenticode, and does not silently fall back to Git/WSL/new preview clients.
The SSH SERVER fixture is the separately downloaded official Microsoft
10.4.0.0p1-Preview ZIP pinned to SHA256
`b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957`.
That preview server is test infrastructure, not a recommended production backend.

The fixture generates disposable keys, pins its host public key, binds sshd to
127.0.0.1 with a private configuration, restricts forwarding destinations to
loopback, authenticates only the current test account with its generated key,
and cleans up only owned child processes. It installs NO service, changes NO
firewall/DNS/registry/code-integrity setting, and uploads NO private SSH key,
known_hosts, paths, raw auth log or source credential.

Required acceptance:
- 128 real channels through the Rust-managed Windows OpenSSH child;
- 64/128/192/256/512 excess request bursts rejected at the managed budget;
- held binary byte integrity, same child PID, zero leaked admission permits;
- 10,000 authenticated channel churn, half-close and observed Windows HANDLE
  recovery (HANDLE count is NOT the OpenSSH internal descriptor table);
- four independent SSH child processes through the actual owned-supervisor ABI,
  2->4->3->2 transitions, pause/resume and no DIRECT;
- a SEPARATE bare-backend probe with a ceiling of 512 and at least 128 actual
  byte-verified held channels, resource-error counters, real attempt counts and
  post-release forwarding. Failure/zero success cannot produce a PASS.

The script's existence and seven synthetic negative-contract unit tests do
not constitute a Windows run. Preserve exact workflow ID/SHA and the emitted
JSON after a real successful execution. Keep Issue #7 open for user's OS,
WFP+SSH medium-integrity capture, fairness and sustained multi-hour soak.

References: Microsoft Windows OpenSSH server configuration (custom `sshd -f`
and authorized-key ACLs); PowerShell/Win32-OpenSSH official release 10.4.0.0p1-Preview
asset 645185877. The fixture never bypasses host-key or binary-signature checks.
