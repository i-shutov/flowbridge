# R140 persistent enforcement — separate design gate, no installation

Status: NOT IMPLEMENTED, NOT AUTHORIZED, RELEASE NO-GO.

R19 policy_windows.rs creates a DYNAMIC BFE session. Microsoft documents that
objects owned by a dynamic session are automatically removed on session close
or owning process termination. A user-mode STOP or kernel callback cannot deny
traffic after its entire filter is absent. Read-only R129 reported four NOT_FOUND
responses on the owner's Windows 10; those observations are consistent with
the research policy not being installed, not a failure of the BFE API.

Candidate future design, subject to independent review and lab permission:
- A separately owned, durable deny-by-default selected-app egress barrier.
- A formally disjoint, proof-carrying exception for permitted redirected flows.
- No broad localhost/port/hostname/PID-only allow; prove original vs proxy AppId.
- State machine: BLOCKING_BASELINE / REDIRECT_READY / REVOKING / RECOVERY.
- Explicit WFP arbitration for hard permits/blocks, veto and filter ordering.
- Explicit IPv4+IPv6, TCP, UDP/QUIC and DNS/out-of-process resolver scope.
- BFE service-loss, power loss, reboot and uninstall tested; no foreign deletion.
- Only after signed driver, snapshots, separate console rescue and rollback gate.

Acceptance matrix: broker hard crash, BFE/dynamic-session loss, SSH loss, PID reuse,
5-tuple reuse, selected/same-basename siblings, IPv4/IPv6, DNS/QUIC and service
recovery must each have native readback plus external traffic evidence.
ALL are NOT RUN and NO-GO. Static denial cannot be naively introduced now:
it could also block the legitimate redirect path.

Primary documentation:
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
