FlowBridge — INTERNAL NATIVE BETA CANDIDATE

This installer includes the GUI, Rust transport, elevated WFP helper, and reversible DNS policy helper. It does NOT include or install a kernel driver. Native interception requires the separately installed, signed FlowBridgeWfp driver matching this source revision. Do not disable Windows security or change boot settings merely to try this package.

Local SOCKS mode works without the driver. Native mode is selected on Applications and requires integrated SSH, selected executables and approval of the helper's elevation prompt. SSH and private-key handling remain in the user's unelevated process. The helper is installed in Program Files\FlowBridgeBeta.

Remote DNS is checked by default. It uses an explicit IP resolver on the SSH server or reads that server's POSIX /etc/resolv.conf through authenticated SSH. No public resolver is substituted. In this beta, use a numeric SSH server IP to avoid DNS bootstrap recursion. DNS applies to standard DNS for the entire Windows machine, not just selected applications. Existing corporate/third-party NRPT policies are refused rather than overwritten. Split DNS, remote hosts/NSS and app-owned DoH/DoT are not reproduced by this transport.

During native mode the selected executable paths have outbound non-loopback UDP/443 blocked to allow TCP fallback. Re-scan after an application's executable path changes. Other UDP is not tunneled. With remote DNS enabled, non-loopback UDP/TCP port 53 is blocked; the owned loopback stub remains available. These are not HTTPS interception or universal encrypted-DNS controls.

Stop removes the owned WFP filters and DNS rule. An independent guardian removes only the exact owned DNS rule if its listener process dies; user profiles and adapter DNS configuration are preserved. A helper failure is displayed as an error. This candidate is not a persistent system-wide kill switch after the whole product exits.

The watchdog recovers new connections, NOT already-established TCP sessions after SSH dies. No application request is replayed.

Verified test evidence is associated with the exact Git commit in CI artifacts. A compiled WFP driver / unsigned macOS extension is not proof of OS activation or end-to-end kernel interception. Do not describe this candidate as a completed full beta until those acceptance gates pass.
