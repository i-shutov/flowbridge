# R17 — direct socket-to-ALE endpoint collection for G2 research

Date: 2026-11-07. Only `research/windows-wfp-ale-attribution-20261107`.
Initial baseline `f92d2e580b6c394b29e977d76466918fb6000cc7`.
Concurrent R16 advanced HEAD to `77021756fd192ca17f6bf7dad89dc310da03b696`;
its three-file health-latch change was read and is preserved unchanged.
Main observed `5b5afc2feeda2195f302380e615ba003d4906e09`.

## New documented source, not another tuple join

Microsoft documents this user-mode path:

```
caller-owned connected TCP socket
 -> WSAIoctl(SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE)
 -> actual UINT64 transport endpoint identifier
 -> FwpsAleEndpointGetById0(local BFE query session, that exact identifier)
 -> FWPS_ALE_ENDPOINT_PROPERTIES0.appId
```

The Winsock IOCTL explicitly maps a socket handle to a transport endpoint.
The endpoint query is documented in `fwpsu.h` with `fwpuclnt.lib`.
This is not an IP Helper/ETW 5-tuple, filename or timing correlation.
Native support/permissions and behavior still require an actual Windows test.

**Critical boundary:** the full endpoint properties structure has endpointId,
addresses, ports, protocol, token-modified/IPsec identifiers, flags and AppId.
It has NO PID, creation epoch, ProcessStartKey or EPROCESS. TokenModifiedId is
not a process generation. An accepted proxy socket identifies its local endpoint,
not the original remote application's process. Duplicated socket handles are
another reason not to substitute the querying process's PID for the creator.

## Actual code, deliberately not an owner authorizer

`socket_endpoint_r17.rs` is a clean-room user-mode Rust module whose entry point
borrows `&TcpStream`; no arbitrary raw-handle argument, public observation
constructor or Clone. It reads the exact endpoint's AppId and queries redirect
records/context on that same socket, with bounded buffers and RAII cleanup.
The observation retains the socket borrow. Original-owner and G2 admission
flags are unconditionally false. No production capture pipeline is changed.

`socket_endpoint_r17.py` independently implements the native query through
ctypes. Its consented CLI opens only one local IPv4 or IPv6 loopback TCP pair,
sends no payload, and exposes neither foreign-host nor PID/handle arguments.
It closes sockets and BFE session and exports only booleans, lengths and error
codes, never AppId bytes, endpoint IDs, addresses, process IDs or raw receipts.

Neither implementation enumerates TCP tables, looks up a process, creates a
filter/callout/driver, redirects traffic or sets redirect records. Read buffers
are capped at 64 KiB with no retry/fallback. Mandatory endpoint query errors,
wrong endpoint/protocol/family, invalid AppId and observed endpoint changes fail
collection. Optional redirect query errors remain errors, NOT proved absence.
Even successful opaque records/context are not authenticated original-owner
identity and never grant admission. Repeated endpoint IDs are a consistency
check, not a complete lifetime/recycle proof.

## Additional identity API findings

`PsGetProcessStartKey(PEPROCESS)` is documented as unique across boot sessions
(Windows 10 1703+, IRQL <= DISPATCH). It still requires the correct referenced
EPROCESS from the original classify. It does not recover that object from an
NDISRD buffer, filename or proxy-side socket.

`EVENT_EXTENDED_ITEM_PROCESS_START_KEY` identifies the process LOGGING the ETW
event. It cannot be assumed to identify the original network owner. This closes
another tempting but unsupported way to promote logger metadata to G2 proof.

## Executed verification and non-results

Linux/Python 3.13.5: 32/32 tests of the actual Python control flow and ctypes
allocation wrappers PASS. All Windows API calls in these tests are mocked.
Six deliberately unsafe mutants were detected by a separate test harness:
foreign endpoint acceptance, ignored endpoint change, false G2 PASS, query error
reported as absence, omitted allocation release, and mutating IOCTL admission.
Python syntax compilation PASS. The actual CLI on this executor returned exit 2,
`windows_x64_required`, before any socket operation.

The Rust module is source-written, NOT compiled or executed in this cycle: no
local compiler is installed and the official download host was unavailable.
No Windows-native R17 run or independent human/native reviewer sign-off occurred.
Previous R14/R15 native results do not transfer to this source.

An initial mutation-harness run found its own non-unique edit anchor. The anchor
was narrowed without changing the collector; the final six-mutant run passed.
No native failed workflow was rerun.

Reproduce offline:

```sh
python3 -m unittest discover -s research/wfp-ale -p test_socket_endpoint_r17.py -v
python3 research/wfp-ale/mutation_socket_endpoint_r17.py
```

On an already-authorized Windows executor (NOT run here):

```powershell
python research/wfp-ale/socket_endpoint_r17.py --consent G2_SOCKET_ENDPOINT_READONLY --family ipv4
python research/wfp-ale/socket_endpoint_r17.py --consent G2_SOCKET_ENDPOINT_READONLY --family ipv6
rustc --edition=2021 --crate-type lib research/wfp-ale/socket_endpoint_r17.rs
rustc --edition=2021 --test research/wfp-ale/socket_endpoint_r17.rs -o r17-tests.exe
```

## Trust map and execution constraint

| Link | Result |
|---|---|
| Socket -> ALE endpoint ID | Direct documented API; collector implemented, native R17 NOT RUN |
| Endpoint -> AppId | Direct documented query; returned schema has no PID/epoch |
| Proxy accepted endpoint -> original client's process | Still unproved; local endpoint is not remote origin |
| Original classify -> pinned EPROCESS/start key/epoch | Still requires approved kernel-origin witness |
| Optional records/context -> own authenticated redirect | Blob presence alone cannot establish this |
| NDISRD frame -> kernel owner | Common per-frame token still missing |

G2 remains OPEN. This is a new collection mechanism for a local-socket sublink,
not full ownership acceptance. No no-DIRECT, DNS/UDP containment or release claim.
G1 acceptance remains confined to dd1ab3c; beta/main/PR #56 were not changed.

The current connector has no workflow_dispatch operation. No push/issue-trigger
workaround, paid browser, new credentials or agent was introduced. Historical
R12/R14/R15 push-triggered runs do not waive the owner's explicit no-bypass rule.
Only research/wfp-ale files change; none match those workflow-file path triggers.

The next decisive permitted test is this direct local-socket query, separating
accepted and outbound endpoints and ordinary sockets without redirect evidence.
It cannot replace a later original unprepared EXE/sibling/PID-reuse test. Actual
kernel redirection still requires the separately authorized signed backend and
all VNC, SYSTEM rescue, security and rollback gates.

## Primary Microsoft references checked 2026-11-07

- https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_ale_endpoint_properties0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessstartkey
- https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_process_start_key
