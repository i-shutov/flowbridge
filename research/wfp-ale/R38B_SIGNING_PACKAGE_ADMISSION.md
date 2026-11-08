# R38B — signed-driver admission preparation (unsigned submission candidate)

Scope: only `research/windows-wfp-ale-attribution-20261107`. **No executable driver was signed, loaded or installed by this step.**

## Artifacts and controls

`kernel-r19/signing-r38/flowbridge_g2_r38.inf` is a **review candidate** for a Windows 10/11 x64 non-PnP primitive driver. It declares demand-start (`StartType=3`) and a driver service; it cannot itself provide a signature or activate a BFE filter. Target class, INF schema, publisher identity, DriverStore placement and catalog readiness require independent InfVerif and Partner Center acceptance. The publisher text is intentionally research-only; it is not a claim of EV ownership.

`prepare_submission_r38.ps1` runs only after a source-pinned, passing Windows-hosted kernel+broker build. It checks:
- exact GitHub commit vs `build-result.json` and `r24-build-scope.json`;
- unsigned driver and broker SHA256, and explicit no-load/no-BFE/no-G2 flags;
- Windows Authenticode reports unsigned source (unexpected signing stops);
- copies the exact .sys and INF into a short named folder, builds a CAB with Windows `MakeCab`, re-extracts it with `Expand`, and verifies member SHA256;
- records all byte-level evidence in `R38_UNSIGNED_SUBMISSION.json` without marking INF, Partner Center, signature, host admission, kernel load or G2 as PASS.

`compare_pe_sections_r38.py` independently compares exact unsigned source and a future Partner Center-signed returned .sys: all x64 Native PE section bytes, RVAs, sizes and flags must remain identical. It does **not** verify a signature; Microsoft may change PE checksum and certificate directory, so whole-file signed SHA is expected to differ.

`preflight_r38.ps1` is **read-only** on the intended Windows 10/11 desktop. It demands exact pinned hashes of unsigned .sys, returned signed .sys, broker and the signed catalog. It invokes `SignTool verify /kp /v /c <catalog> <signed.sys>`, compares executable section bytes, observes Secure Boot and DeviceGuard and rejects an already-installed research service. It outputs a JSON record but **always exits nonzero and never sets `host_admitted_for_R39`**: current independent VNC test, SYSTEM rescue, rollback, accepted publisher/InfVerif package, and physical network observer still require external evidence that cannot be produced from GitHub-hosted CI.

## Correct Microsoft signing route and external dependencies

Microsoft's current attestation guidance for testing says Windows Desktop 10+ is supported, and Partner Center hardware submissions require an organization linked to a valid EV certificate. The submission CAB should contain the driver and INF; the CAB is signed using the registered EV certificate, submitted to Partner Center, and Microsoft returns a signed driver/catalog package. **No EV private key, Partner Center connection or Microsoft signature is present in this research repository.** No test-signing mode or disabling Secure Boot/HVCI/Defender is authorized as a workaround. Server 2025 is a build host, **not evidence** that an attestation-signed desktop driver will be accepted on Server.

References (official):
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs
- https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/creating-a-primitive-driver
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/verifying-the-release-signature

## Source acceptance checklist before R39

1. R38A kernel lease revocation has a successful *exact-source* Windows/no-load and native Linux OpenSSH test. Its user-mode stop does not guarantee the kernel blocked already-buffered bytes or survived a broker crash.
2. The CAB, INF and exact unsigned kernel/broker hashes are pinned to one source SHA; independent INF validation and Microsoft Partner Center submission/publisher approval occur outside CI.
3. The signed .sys/.cat are returned and verify with `SignTool /kp` on the actual intended Windows desktop without weakening protections. The signed PE loadable sections match the pinned unsigned source.
4. Before any load, an independent operator proves **current** VNC connectivity and SYSTEM rescue on the exact target; prepares and tests a rollback of the exact service/filter rules and verifies physical egress instrumentation. The signed image and machine baseline are recorded.
5. Only then R39 may begin: an unmodified selected EXE starts after kernel callback attachment, an actual single flow traverses redirected ALE, authenticates AUTH ticket and accepted-socket WFP records, the physical SSH socket is marked before connect, host-key/user SSH identity and direct-tcpip channel are verified, and exact target bytes are echoed. Negative sibling/PID reuse/endpoint ABA/SSH/BFE loss and physical no-DIRECT remain separate required checks.

As of preparation: `kernel_driver_loaded=false`, `partner_center_submission_complete=false`, `microsoft_signature_verified=false`, `host_admitted_for_R39=false`, `g2_pass=false`, `release_accepted=false`.

**Do not publish or install an unsigned CAB as a driver.**
