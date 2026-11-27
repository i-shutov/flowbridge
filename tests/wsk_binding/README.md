# WFP accepted WSK socket binding prototype

The ABI4 broker accepts a Windows socket and asks the transport for redirect data. Its terminal IOCTL then sends copied context to the driver. A successful ABI4 claim identifies an existing kernel AUTH ticket. The driver cannot inspect the socket object through that IOCTL. The Win11 owned-socket ALE probe verified a useful property of the public transport handle. G2 still requires a kernel-owned path from the accepted socket through the origin receipt and the physical flow.

This directory builds an isolated WDK object, outside the product driver and installer. A future kernel worker can supply a privately owned WSK listener and its immutable policy-generation identity to `FbWskAcceptBound`. The prototype takes the accepted object from the completed `WskAccept` IRP. It checks the returned listener address, then asks WSK for the context and opaque records on that same object. Only a successful exact-size context query and a nonempty bounded record query reach the ABI4 terminal receipt logic. The lock protects the live process epoch, policy check and one-use terminal update together. A rejection drains its IRPs and closes the accepted object. Success returns a private opaque object that retains the accepted socket until `FbWskReleaseBound`.

The worker must supply the owned WSK listener, a live provider NPI, and listener/provider/policy rundown. It must bind the listener's owning process and exact loopback port to the same redirect target PID and policy generation at the WFP callout. Each armed generation needs its own receipt history. In-flight work and accepted sockets require explicit cancellation and drain before disarm or unload. The prototype requests cancellation after each three-second accept/query wait and retains memory until the provider completes the IRP. Close and cancellation drain can block. The 4 KiB record limit is a fail-closed prototype bound. Both queries use the completed IRP size on success.

Signing, real WSK listener startup, redirect record lineage, a native cross-socket transplant attempt, outbound record install, and independent egress evidence remain open. The operating system needs to demonstrate that direct or sibling sockets and a new outbound socket carrying copied records cannot present a valid origin context to the accepted WSK path. Route generation and WSK provider lifetime must be wired and reviewed before any signed runtime test. The current ABI4 driver and its legacy user-mode IOCTL remain outside this prototype.

## Verification

`cmake -S tests/wsk_binding -B BUILD`, build, and CTest exercise nine authority fixtures against the shared ABI4 C logic. These fixtures cover correct single-use authorization, replay, initial AUTH, PID reuse, policy generation, disable, broker mismatch, wrong flow, malformed context, and IPv4/IPv6 listener mismatch. `python tests/wsk_binding/test_object_source.py` guards the WDK call sites against eight source substitutions, including querying a neighboring socket, replacing the accepted object, and offering copied context. These are source controls. The hosted WDK target compiles the WSK translation unit and produces a transient object file.

| Gate | Value |
| --- | --- |
| `g2_accepted` | `false` |
| `origin_process_bound` | `false` |
| `packet_owner_bound` | `false` |
| `driver_runtime_executed` | `false` |
| `published_binary` | `false` |

[Microsoft WskAccept](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_accept) · [Using WSK IRPs](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-irps-with-winsock-kernel-functions) · [WskControlSocket](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_control_socket) · [WFP redirect context](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-query-wfp-connection-redirect-context) · [WFP redirect records](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-query-wfp-connection-redirect-records)
