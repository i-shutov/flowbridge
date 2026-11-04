# G1: upstream EOF and the uncontrolled HTTP oracle

Date: 2026-11-04. Status: confirmed acceptance-design defect; historical transport cause unresolved.

## Exact observations, not hypotheses

Public source `1e81a8941faf6d8988e071d768e6134a1f80a564`, test merge
`a2647c75300e23b79f9fc41eccf47aff41697cbd`; private workflow
`0e7e8873b37a0f82f2c7b615e153c105aa1a5539`.
[Authorized native run 41842286785](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41842286785)
was workflow_dispatch on the protected QA branch, not a push or a rerun.

| Trial | Outcome | Failure boundary |
|---|---|---|
| 1 | FAIL | `ssh_restarted_self`: request 57, relay response 0, completed relay, full SOCKS CONNECT succeeded; 247 ms |
| 2 | 23/23 PASS | Includes unexpected owned SSH death, automatic denial and recovery; recovery response/client both 311 bytes |
| 3 | FAIL | `ssh_restarted_powershell`: request 57, relay response 0; 321 ms; two earlier post-restart HTTP phases succeeded |

Failing trials stopped before the later unexpected-SSH-death block. A false
summary flag for that unreached block is not evidence that automatic recovery
itself failed in these two trials. Neither a completed relay nor a successful
CONNECT proves the HTTP server received the request. The 57 bytes were copied
to the local upstream connection. Ordinary EOF with zero response is valid for
a generic TCP relay and must not be silently retried or relabeled successful HTTP.

The same `inactive_tcp_state/ack_only` denial occurred on successful phases.
No evidence authorizes loosening PID, epoch, TIME_WAIT, ACK, FIN or DIRECT policy.
A simple premature `ready` transition is not a sufficient explanation of trial 3.
It is also too strong to claim that every possible NDISRD contribution is excluded:
the immediate observed gap is upstream, but the exact initiating event is unknown.

## Independently recomputed artifact hashes

The actual downloaded ZIPs were SHA-256 hashed and CRC checked locally on
2026-11-04; each contained one parseable report with the expected source/workflow.
This is byte evidence, not merely copied GitHub provider digests.

| Artifact | ZIP SHA-256 |
|---|---|
| 13330285853, trial 1 | `2742c92c811b73e5bcae10799efbb59809705f99b87322c28a0678d66bd6973b` |
| 13329647659, trial 2 | `4376c6a93836ef54ebb33b73c60651e285588fa1470df36f8865ac29028091ab` |
| 13330126965, trial 3 | `6206528f3ebea3e8edfba6b007d9260dc85b7d9a46ccbcba09c6ee9b59987b9b` |

All three reports preserve mode-zero rollback, healthy network, active Defender,
scoped firewall cleanup and independent SYSTEM rescue armed/disarmed. They are
Server 2025 evidence, not personal Windows 10/11 acceptance.

## Confirmed defect and limits of attribution

The private workflow resolved public `example.com` and required HTTP replies
from port 80. Its initial TCP-connect check did not validate HTTP behavior.
IANA explicitly says these HTTP services are best-effort, not software testing
endpoints, and that behavior/availability can change without notice:

- https://www.iana.org/help/example-domains
- https://www.iana.org/news/2024/example-domain-http-methods

This proves an invalid acceptance dependency, **not that IANA caused either
specific EOF**. An individual SSH channel/remote origin could have closed; the
retained artifacts have neither server-side request receipts nor SSH channel
traces for those failed requests. Re-reading them cannot manufacture that evidence.
Early TCP half-close is intentionally retained as a transport requirement; removing
it to make an uncontrolled HTTP endpoint green would weaken the original scenario.

## Implemented change in the accompanying source revision

`tests/g1_controlled_origin.py` supplies an owner-operated bounded HTTP fixture,
an independent receipt journal, and ordinary/early-half-close direct and SOCKS
controls. It has no driver, firewall, service, route or SSH configuration actions.
The existing native harness requires explicit controlled-origin consent and a
literal IPv4 identical to the original destination. Missing/legacy input fails
before FFI/SSH/native execution. A local or TEST-NET target cannot masquerade as
physical-adapter evidence. The original 57-byte request and all 23 native phases
remain; `Host: example.com` is retained only as literal request data, never DNS.

At initial setup the independent controls require the exact nonce-bearing response,
not just any HTTP status. Existing native positive assertions are additionally
checked against its deterministic byte length. On a native failure, controls run
only after its own rollback and external-client exit are confirmed. The original
failure remains a failure; no retry or pre-recovery warm-up is inserted.

Important boundary: existing Rust native reports expose response length, not a
response digest. Native per-phase content identity therefore still requires the
independently collected origin receipts and reviewer correlation. A server
`response_write_completed` means accepted by its local socket, not proven client
delivery. Neither the fixture tests nor the origin control result closes G1.

## Decisive next observation

Use the independently controlled endpoint and correlate its request/response
receipts with the failing native phase and the post-rollback controls. If origin
receipt exists and it wrote the response but the relay saw zero, investigate the
SSH/return transport. If the origin never received the request, investigate request
delivery. A failed direct control makes origin/network availability a confounder;
a passing direct control with failed SOCKS narrows the boundary but is not, by
itself, proof of the earlier request's cause. Controls are subsequent observations,
not simultaneous counterfactuals. No speculative transport patch is justified yet.

See [the release plan](../plans/windows-release-g0-g6.md) and
[controlled-origin rollout](../docs/qa/G1_CONTROLLED_ORIGIN.md).
