# WFP accepted WSK socket binding prototype

The ABI4 broker accepts a Windows socket and asks the transport for redirect data. Its terminal IOCTL then sends copied context to the driver. A successful ABI4 claim identifies an existing kernel AUTH ticket. The driver cannot inspect the socket object through that IOCTL. The Win11 owned-socket ALE probe verified a useful property of the public transport handle. G2 still requires a kernel-owned path from the accepted socket through the origin receipt and the physical flow.

This directory builds an isolated WDK object, outside the product driver and installer. `FbWskAcceptBound` takes the listener and generation authority from one opaque kernel owner. The prototype takes the accepted object from the completed `WskAccept` IRP. It checks the returned listener address, then asks WSK for the context and opaque records on that same object. Only a successful exact-size context query and a nonempty record query within the 4 KiB cap reach the ABI4 terminal receipt logic. One authority lock protects the live process epochs, policy check and one-use terminal update together.

## Ownership and shutdown

`FbWskCreateOwner` allocates a disarmed owner with a fresh generation receipt history, exact loopback address and nonzero port, and a reference to the designated process object. It derives the PID, creation time and start key from the kernel object. The host supplies its nonpaged authority lock and process-notify epoch table and retains them through owner destruction. Each generation uses a separate owner.

`FbWskStartOwner` registers WSK, captures the provider without waiting for it to become available, creates a TCP listen socket, and binds the exact IPv4 or IPv6 loopback address using the owner's nonpaged IRP and address storage. Socket creation and bind each wait for completion on the serialized owner at PASSIVE_LEVEL, with no completion deadline. Startup failures preserve partially acquired resources for the same shutdown path. The process argument to `WskSocket` selects the security context used for local address sharing. The WFP callout still needs to use the same target PID, address, port and generation, and native testing must establish the resulting transport properties.

`FbWskArmOwner` requires successful bind and an exact live broker epoch. A future WFP callout can acquire the same authority lock through `FbWskLockOwnerAuthority` to use the target and receipt history, then release the lock through `FbWskUnlockOwnerAuthority`. Admission and terminal claim also check the live broker incarnation. `FbWskStopOwner` closes binding admission and disarms authority together under the same lock. A binding admitted before stop can finish its WSK calls, and a terminal claim ordered after stop fails without consuming a receipt. An owner can arm once, with a fresh owner required for a new generation.

`FbWskAcceptBound` shares one three-second completion-wait budget across accept and both queries. Windows scheduling, clock granularity, and time spent in WSK dispatch calls govern when the caller actually returns. Rejection or timeout after allocation transfers a cleanup-only handle to the caller and leaves the bound result empty. The pending IRP, accept address, completion event and query buffers stay in nonpaged storage. `FbWskReleaseBound` moves a successful binding to the same cleanup path and clears the bound handle.

The owner advances cleanup with `FbWskDrainBound` until it consumes the handle or reports a close failure. Each invocation observes completion without waiting. A step can invoke provider code through `IoCancelIrp` or `WskCloseSocket`, so run drain on the owner side of the timeout response. The owner serializes and synchronizes each handle handoff, and schedules further drain calls when the result is `STATUS_PENDING`. Cancellation is requested at most once per abandoned accept or query. Cleanup collects a socket from an accept that succeeds late, discards late query results and issues close once after the previous IRP completes. Resources remain owned until actual completion and successful close when a socket was acquired. A completed close failure leaves the cleanup handle quarantined and retains its outstanding count. Provider completion or close can remain unresolved indefinitely.

`FbWskStopOwner` reports `STATUS_DEVICE_BUSY` and the outstanding binding count while any admitted, bound, draining or quarantined handle remains. After the count reaches zero, serialized calls to `FbWskAdvanceOwnerRundown` perform the following sequence.

1. Run the host's join barrier, which withdraws publication of the owner and joins all external callers, callouts and workers that can use it.
2. Submit listener close once, then sample its completion on subsequent calls. A pending close keeps the owner live. A completed close failure quarantines the owner and keeps the captured provider and registration.
3. Release the provider capture, when acquired, and wait for `WskDeregister` to return when registered.
4. Run the host's separate callback-return barrier, then free owner storage, release the process reference, and clear the owner handle.

`FbWskComplete` signals its event before returning. The event proves I/O result availability. The separate return barrier must account for all startup, binding and close completion routines and any event callbacks the host adds. The isolated object provides the required integration point for that barrier. A real host implementation and native verification remain prerequisites for an unload claim. The current WSK registration and sockets supply no event callback dispatch.

Signed Windows 11 runtime execution, live listener startup, completion and cancellation races, callback-return and unload behavior, route generation integration, redirect record lineage, outbound record install, and independent egress evidence remain open. Native tests need to establish rejection of connections without valid redirect provenance. The current ABI4 driver and its legacy user-mode IOCTL remain outside this prototype.

## Verification

`cmake -S tests/wsk_binding -B BUILD`, build, and CTest exercise nine authority fixtures, nine binding lifecycle fixtures, and seven owner fixtures. Owner fixtures cover stop versus an admitted claim, broker PID reuse, unopened admission, outstanding handle retention, caller and worker join, successful and failed listener close, and the separate callback-return gate. `python tests/wsk_binding/test_object_source.py` guards the WDK call sites against eight authority substitutions, twelve binding lifecycle substitutions, and eighteen owner substitutions. The portable fixtures exercise shared decisions with controlled inputs. The hosted WDK target produces a transient object file.

| Gate | Value |
| --- | --- |
| `g2_accepted` | `false` |
| `origin_process_bound` | `false` |
| `packet_owner_bound` | `false` |
| `driver_runtime_executed` | `false` |
| `published_binary` | `false` |

[WSK registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/registering-a-winsock-kernel-application) · [Microsoft WskSocket](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_socket) · [WskBind](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_bind) · [WskAccept](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_accept) · [Using WSK IRPs](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-irps-with-winsock-kernel-functions) · [WskControlSocket](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_control_socket) · [IoCancelIrp](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocancelirp) · [WskCloseSocket](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_close_socket) · [WSK deregistration](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/unregistering-a-winsock-kernel-application) · [WFP redirect context](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-query-wfp-connection-redirect-context) · [WFP redirect records](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-query-wfp-connection-redirect-records)
