# R76 — WFP net-event cannot certify failed redirect receipt

2026-11-09. Scope ONLY research/windows-wfp-ale-attribution-20261107. Parent research HEAD: `d13a6a31e42e688c3019efab0ecdf0b1550d150d`; observed main: `5b5afc2feeda2195f302380e615ba003d4906e09`. Not beta, PR #56, PacketBound/G2, leak-free, or G1 promotion from dd1ab3c.

## Decisive NO-GO

Microsoft `FwpmNetEventSubscribe2` and `FwpmNetEventEnum2` expose net-event notifications and logged historical events, not an attested, lossless, one-to-one `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS)` failure receipt. `FWPM_NET_EVENT_CALLBACK2` receives `FWPM_NET_EVENT3`; its `FWPM_NET_EVENT_HEADER3` includes timestamp, AppId, family, protocol, addresses, ports, scope, user SID, EDP data, but not original process creation epoch, accepted SOCKET identity, redirect-record handle, endpoint generation or per-receipt nonce. `FWPM_NET_EVENT_CLASSIFY_DROP2` adds filter/layer/reauth/direction/profile data, not those missing identities. `FWPM_NET_EVENT_SUBSCRIPTION0.sessionKey` identifies the subscription session rather than the flow. A matching AppId+5-tuple+timestamp cannot authenticate accepted-socket-to-CLAIM binding, nor exclude concurrent sibling DIRECT.

The official WFP Logging page describes a bounded circular log (historically documented as 128 KiB / roughly 100–150 entries), overwrite, empty-on-reboot and possibly disabled logging. That old capacity is not claimed as a Windows 11 measured limit. `FwpmNetEventEnum2` snapshots events logged prior to enum-handle creation and can return `FWP_E_NET_EVENTS_DISABLED`. Silence or empty enumeration does not certify absence of a selected connection/event. The subscription API does not document lossless delivery, a per-flow monotonic sequence, or a failure heartbeat. Do NOT invoke `FwpmEngineSetOption0` as logging settings are machine-wide and persistent.

## Reproducible independent negative tests

Run `python research/wfp-ale/r76/r76_negative.py` (5 unit tests), then `python research/wfp-ale/r76/r76_negative.py --oracle` and `node research/wfp-ale/r76/r76_independent.mjs`. Both independent implementations cover **10,240 synthetic states**: IPv4/v6, TCP/UDP, event AppId/tuple/timestamp/flags match, original process epoch match/mismatch, same/different accepted socket, event delivered/missing, five log modes, selected/foreign owner, sibling DIRECT on/off. These are deterministic counterexamples, NOT native WFP observations.

Unsafe naive correlator: 160 plausible joins, **140 false identity joins**, **80 false no-DIRECT assertions**; log history hypothetically incomplete in 8,192 states. The numbers overlap and are model-only. Even a perfect match to all observable event fields admits two worlds with different original process epochs or accepted socket. An event can coexist with an unrelated socket; an unobserved event might have been overwritten/not collected. The guard refuses to promote telemetry to identity or leak-free. Python/Node per-world ordered SHA256:
`746f152c7a76ac8c6dfea39fe0bc0347964c771cb59c2472179fb7777d9ef7fd`.

## Exact trust boundary, next decisive experiment

`FwpmGetAppIdFromFileName0` gives ALE AppId, not lifetime identity. Kernel `ALE_CONNECT_REDIRECT_V4/V6`, `ALE_AUTH_CONNECT_V4/V6`, query-before-issue `FwpsQueryConnectionRedirectState0`, referenced original EPROCESS/creation epoch, redirect records/context on accepted socket, one-use CLAIM and authenticated SSH remain separate unproved links. Especially process death/PID reuse, reused 5-tuple, IPv6 scope, sibling DIRECT, DNS/UDP/QUIC and WFP/SSH loss cannot be certified by net events. Current kernel-r19 broker pre-receipt error yields IngressRejected (R74/R75); no claim of actual leak or physical PASS.

**R77:** do not build another event-log correlator. Prefer read-only native Windows owned-socket `WSAIoctl` sizing/error probe (NOT a redirected-flow experiment) plus offline Rust accepted-socket typestate/CLAIM fault matrix. Kernel callout/driver/filter, VNC/SYSTEM rescue and physical no-DIRECT work remain forbidden without separate owner gates. No machine, security, runner, network, automation, main/release/beta or PR #56 changes.

Official API docs (checked 2026-11-09):
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe2
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nc-fwpmu-fwpm_net_event_callback2
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event3
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_header3
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_classify_drop2
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_subscription0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventenum2
- https://learn.microsoft.com/en-us/windows/win32/fwp/logging
