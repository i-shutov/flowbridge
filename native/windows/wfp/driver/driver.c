/* Original FlowBridge WFP callout. Build with WDK, not a user-mode SDK.
 * Inline classify only: no pending packets, work items, or user pointers. */
#include <ntddk.h>
#include <wdmsec.h>
#include <fwpsk.h>
#include <ws2ipdef.h>
#include "../control.h"
#include "../redirect_context.h"
#include "../process_epoch.h"
#include "../auth_receipt.h"
#define FB_POOL_TAG 'rBbF'
C_ASSERT(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES);
static PDEVICE_OBJECT gDevice;
static HANDLE gRedirect;
static UINT32 gCallout4, gCallout6, gAuthCallout4, gAuthCallout6;
static KSPIN_LOCK gLock;
static FbEpochTable gEpochTable;
static FbAuthBook gAuthBook;
static BOOLEAN gEpochNotifierRegistered;
static PFILE_OBJECT gOwner;
static HANDLE gOwnerPid;
static FbWfpConfig gConfig;
static BOOLEAN gEnabled;
static BOOLEAN gLinkCreated;
static volatile LONG64 gFlowId;
static UNICODE_STRING gLink = RTL_CONSTANT_STRING(L"\\DosDevices\\FlowBridgeWfp");

/*
 * WFP process creation is an OS-origin event at PASSIVE_LEVEL. We capture
 * immutable PsGetProcessCreateTimeQuadPart and PsGetProcessStartKey ONCE.
 * An old process existing before driver startup has no entry and MUST fail
 * closed until it is relaunched under the notifier. No user-space PID table.
 *
 * This is still an identity component, not complete G2: ALE_AUTH_CONNECT,
 * BFE competing filters, redirect-record consumption and physical egress
 * must independently be accepted.
 */
static VOID NTAPI FbProcessNotify(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info) {
    KIRQL irql;
    FbEpochRecord record;
    if (process == NULL || pid == NULL) return;
    record.pid = (FbUint64)(ULONG_PTR)pid;
    record.process_token = (FbUint64)(ULONG_PTR)process;
    record.creation_100ns = (FbUint64)PsGetProcessCreateTimeQuadPart(process);
    record.start_key = (FbUint64)PsGetProcessStartKey(process);
    KeAcquireSpinLock(&gLock, &irql);
    if (info != NULL) {
        if (info->CreationStatus >= 0 && !gEpochTable.lost) {
            (void)FbEpochInsert(&gEpochTable, record);
        }
    } else {
        (void)FbAuthProcessExit(&gAuthBook, record.pid, record.creation_100ns, record.start_key);
        (void)FbEpochExit(&gEpochTable, record);
    }
    KeReleaseSpinLock(&gLock, irql);
}
static void FbBlock(FWPS_CLASSIFY_OUT0* out) {
    out->actionType = FWP_ACTION_BLOCK;
    out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}
/* Issue after kernel selected-source validation; a user-supplied PID/path or
 * redirect blob cannot enqueue an AUTH receipt. The same spinlock serializes
 * process departure, route disable and ticket insertion.
 */
static BOOLEAN FbIssueOriginalReceipt(const FbRedirectContext* context,
                                      HANDLE broker) {
    FbAuthOrigin item = {0};
    FbEpochRecord current = {0};
    KIRQL irql;
    int ok = 0;
    if (!context || !broker || context->ipv6_scope_id)
        return FALSE;
    item.pid = context->original_process_id;
    item.creation_100ns = context->original_process_creation_100ns;
    item.process_start_key = context->original_process_start_key;
    item.endpoint = context->original_transport_endpoint;
    item.flow_id = context->flow_id;
    item.broker_pid = HandleToULong(broker);
    item.port_be = context->destination_port_be;
    item.family = (context->address_family == AF_INET) ? 4 :
                  (context->address_family == AF_INET6) ? 6 : 0;
    RtlCopyMemory(item.original_ip, context->destination_address, 16);
    KeAcquireSpinLock(&gLock, &irql);
    if (gEnabled && !gEpochTable.lost && !gAuthBook.lost &&
        FbEpochLookup(&gEpochTable, item.pid, &current) &&
        current.creation_100ns == item.creation_100ns &&
        current.start_key == item.process_start_key)
        ok = FbAuthIssue(&gAuthBook, &item);
    KeReleaseSpinLock(&gLock, irql);
    return (BOOLEAN)ok;
}

/* An AUTH classification only matches the selected *current* OS ALE_APP_ID
 * in BFE. ALE_ORIGINAL_APP_ID may still be selected on the physical proxy's
 * records-tagged SSH socket (R198), so it is NEVER used as the filter key.
 *
 * The kernel-origin ticket permits exactly the original selected connection
 * redirected to OUR local broker. A direct sibling, wrong PID epoch, wrong
 * redirect target or external SSH socket cannot consume that ticket.
 * A second physical-SSH exception is NOT minted by broker PID.
 */
static BOOLEAN FbAuthObserved(const FWPS_INCOMING_VALUES0* values,
                              const FWPS_INCOMING_METADATA_VALUES0* metadata,
                              HANDLE broker, FbWfpConfig config,
                              FbAuthOrigin* observed) {
    BOOLEAN v4;
    UINT32 protocolIndex, flagsIndex, appIndex, ipIndex, portIndex;
    UINT32 flags;
    FWP_BYTE_BLOB* app;
    FbAuthOrigin candidate = {0};
    const SOCKADDR* addr;
    if (!values || !metadata || !observed || !broker ||
        !values->incomingValue) return FALSE;
    v4 = (values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4);
    if (!v4 && values->layerId != FWPS_LAYER_ALE_AUTH_CONNECT_V6) return FALSE;
    protocolIndex = v4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL :
                         FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
    flagsIndex = v4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS :
                      FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
    appIndex = v4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID :
                    FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID;
    ipIndex = v4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS :
                   FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
    portIndex = v4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT :
                     FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
    if (protocolIndex >= values->valueCount || flagsIndex >= values->valueCount ||
        appIndex >= values->valueCount || ipIndex >= values->valueCount ||
        portIndex >= values->valueCount) return FALSE;
    if (values->incomingValue[protocolIndex].value.type != FWP_UINT8 ||
        values->incomingValue[protocolIndex].value.uint8 != IPPROTO_TCP ||
        values->incomingValue[flagsIndex].value.type != FWP_UINT32)
        return FALSE;
    flags = values->incomingValue[flagsIndex].value.uint32;
    /* Reauth is a separate lifecycle and must never replay the initial
     * one-shot receipt; leave it blocked until independently accepted. */
    if ((flags & FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED) == 0 ||
        (flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0) return FALSE;
    if (!FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_ID) ||
        !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) ||
        !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID) ||
        !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_ORIGINAL_DESTINATION) ||
        !metadata->processId || !metadata->transportEndpointHandle ||
        !metadata->originalDestination ||
        metadata->localRedirectTargetPID != HandleToULong(broker) ||
        metadata->processId == (UINT64)(ULONG_PTR)broker) return FALSE;
    if (values->incomingValue[appIndex].value.type != FWP_BYTE_BLOB_TYPE)
        return FALSE;
    app = values->incomingValue[appIndex].value.byteBlob;
    if (!app || !app->data || app->size < 2 ||
        app->size > FB_PROCESS_PATH_CHARS * sizeof(UINT16) ||
        (app->size & 1)) return FALSE;
    /* BFE's exact full-path ALE_APP_ID condition matched the current source.
     * Merely having a nonempty ORIGINAL_APP_ID is not a broker exemption. */
    if (values->incomingValue[portIndex].value.type != FWP_UINT16 ||
        values->incomingValue[portIndex].value.uint16 !=
            RtlUshortByteSwap(v4 ? config.port_v4_be : config.port_v6_be))
        return FALSE;
    if (v4) {
        if (values->incomingValue[ipIndex].value.type != FWP_UINT32 ||
            values->incomingValue[ipIndex].value.uint32 != 0x7f000001)
            return FALSE;
    } else {
        FWP_BYTE_ARRAY16* ip;
        UINT8 loopback[16] = {0};
        loopback[15] = 1;
        if (values->incomingValue[ipIndex].value.type != FWP_BYTE_ARRAY16_TYPE)
            return FALSE;
        ip = values->incomingValue[ipIndex].value.byteArray16;
        if (!ip || RtlCompareMemory(ip->byteArray16, loopback, sizeof(loopback)) != sizeof(loopback))
            return FALSE;
    }
    candidate.pid = metadata->processId;
    candidate.endpoint = metadata->transportEndpointHandle;
    candidate.broker_pid = HandleToULong(broker);
    candidate.family = v4 ? 4 : 6;
    addr = (const SOCKADDR*)metadata->originalDestination;
    if ((v4 && addr->sa_family != AF_INET) ||
        (!v4 && addr->sa_family != AF_INET6)) return FALSE;
    if (v4) {
        const SOCKADDR_IN* original = (const SOCKADDR_IN*)addr;
        candidate.port_be = original->sin_port;
        RtlCopyMemory(candidate.original_ip, &original->sin_addr, 4);
    } else {
        const SOCKADDR_IN6* original = (const SOCKADDR_IN6*)addr;
        if (original->sin6_scope_id) return FALSE;
        candidate.port_be = original->sin6_port;
        RtlCopyMemory(candidate.original_ip, &original->sin6_addr, 16);
    }
    /* Birth epoch and start key are supplied from the referenced process
     * callback's live ledger, NEVER from a user-mode table or stream JSON. */
    *observed = candidate;
    return TRUE;
}

static void NTAPI FbAuthClassify(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, void* layerData,
    const void* classifyContext, const FWPS_FILTER1* filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0* out) {
    KIRQL irql;
    HANDLE broker;
    FbWfpConfig config;
    FbEpochRecord process = {0};
    FbAuthOrigin observed = {0};
    BOOLEAN enabled, approved;
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    if (!out) return;
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) {
        /* WFP allows a hard-PERMIT veto; never promote a prior BLOCK. */
        if (out->actionType == FWP_ACTION_PERMIT) FbBlock(out);
        return;
    }
    KeAcquireSpinLock(&gLock, &irql);
    broker = gOwnerPid; config = gConfig;
    enabled = gEnabled && !gEpochTable.lost && !gAuthBook.lost;
    KeReleaseSpinLock(&gLock, irql);
    if (!enabled || !FbAuthObserved(values, metadata, broker, config, &observed)) {
        FbBlock(out); return;
    }
    KeAcquireSpinLock(&gLock, &irql);
    approved = (BOOLEAN)(gEnabled && !gEpochTable.lost && !gAuthBook.lost &&
        FbEpochLookup(&gEpochTable, observed.pid, &process) &&
        process.creation_100ns != 0 && process.start_key != 0);
    if (approved) {
        observed.creation_100ns = process.creation_100ns;
        observed.process_start_key = process.start_key;
        approved = (BOOLEAN)FbAuthConsumeObserved(&gAuthBook, &observed);
    }
    KeReleaseSpinLock(&gLock, irql);
    if (!approved) { FbBlock(out); return; }
    /* Permit ONLY the one-shot original local redirect. Soft action allows
     * Windows firewall and other sublayers to enforce stricter policy. */
    out->actionType = FWP_ACTION_PERMIT;
}

static void NTAPI FbClassify(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, void* layerData,
    const void* classifyContext, const FWPS_FILTER1* filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0* out) {
    KIRQL irql;
    FbWfpConfig config;
    FbEpochRecord processEpoch;
    HANDLE ownerPid;
    BOOLEAN enabled, v4, epochLost;
    UINT32 appIndex, protocolIndex;
    FWP_BYTE_BLOB* app;
    SIZE_T chars, i;
    FbRedirectContext* context = NULL;
    FWPS_CONNECT_REQUEST0* request = NULL;
    UINT64 classifyHandle = 0;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) {
        /* A prior hard PERMIT is not proof of our protected redirect. WFP
         * allows a terminating callout to veto that PERMIT even without
         * ACTION_WRITE; a prior BLOCK must never be changed to PERMIT. */
        if (out->actionType == FWP_ACTION_PERMIT) FbBlock(out);
        return;
    }
    out->actionType = FWP_ACTION_PERMIT; /* soft permit; no firewall override */
    KeAcquireSpinLock(&gLock, &irql);
    enabled = gEnabled; config = gConfig; ownerPid = gOwnerPid;
    epochLost = (gEpochTable.lost != 0);
    KeReleaseSpinLock(&gLock, irql);
    /* Selected dynamic filters may outlive a disable/owner-close callback:
     * returning PERMIT here would silently leak a protected app DIRECT. */
    if (!enabled || epochLost) { FbBlock(out); return; }
    v4 = values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4;
    if (!v4 && values->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) return;
    protocolIndex = v4 ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL;
    appIndex = v4 ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID : FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID;
    if (values->incomingValue[protocolIndex].value.uint8 != IPPROTO_TCP) return;
    if (!FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_ID)) { FbBlock(out); return; }
    if (metadata->processId == (UINT64)(ULONG_PTR)ownerPid) return;
    /* OS-origin endpoint + process PID are mandatory for our selected flow.
     * A PID-only late lookup is not a process-incarnation witness. */
    if (!FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)
        || metadata->transportEndpointHandle == 0) { FbBlock(out); return; }
    KeAcquireSpinLock(&gLock, &irql);
    {
        const int present = FbEpochLookup(&gEpochTable, metadata->processId, &processEpoch);
        KeReleaseSpinLock(&gLock, irql);
        if (!present) { FbBlock(out); return; }
    }
    if (FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
        FWPS_CONNECTION_REDIRECT_STATE state = FwpsQueryConnectionRedirectState0(metadata->redirectRecords, gRedirect, NULL);
        /* A second provider's redirect target is NOT the original selected
         * destination. The previous PERMIT here was an unguarded DIRECT escape.
         * Only self-redirect recursion is permitted to continue; other
         * redirection stays BLOCKED until independently accepted in G2. */
        if (state == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
            state == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) return;
        if (state != FWPS_CONNECTION_NOT_REDIRECTED) { FbBlock(out); return; }
    }
    /* PROCESS_PATH is not available at CONNECT_REDIRECT. ALE_APP_ID is the
     * kernel-supplied UTF-16 executable identity field at this exact layer. */
    if (values->incomingValue[appIndex].value.type != FWP_BYTE_BLOB_TYPE) { FbBlock(out); return; }
    app = values->incomingValue[appIndex].value.byteBlob;
    if (!app || !app->data || !app->size || (app->size & 1) || app->size > FB_PROCESS_PATH_CHARS * sizeof(UINT16)) { FbBlock(out); return; }
    chars = app->size / sizeof(UINT16);
    while (chars && ((UINT16*)app->data)[chars-1] == 0) --chars;
    if (!chars || chars >= FB_PROCESS_PATH_CHARS) { FbBlock(out); return; }
    for (i = 0; i < chars; ++i) if (((UINT16*)app->data)[i] < 32) { FbBlock(out); return; }
#pragma warning(suppress:4996) /* Retain compatibility with older Windows 10 kernels. */
    context = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*context), FB_POOL_TAG);
    if (!context) { FbBlock(out); return; }
    RtlZeroMemory(context, sizeof(*context));
    context->magic = FB_REDIRECT_MAGIC; context->version = FB_REDIRECT_VERSION;
    context->size = sizeof(*context); context->original_process_id = metadata->processId;
    context->flow_id = (UINT64)InterlockedIncrement64(&gFlowId);
    context->process_path_chars = (UINT16)chars;
    context->original_process_creation_100ns = processEpoch.creation_100ns;
    context->original_process_start_key = processEpoch.start_key;
    context->original_transport_endpoint = metadata->transportEndpointHandle;
    RtlCopyMemory(context->process_path, app->data, chars * sizeof(UINT16));
    /* The API takes an opaque non-const pointer although classifyFn receives const. */
    status = FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(context, FB_POOL_TAG); FbBlock(out); return; }
    status = FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0, (PVOID*)&request, out);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(context, FB_POOL_TAG); FwpsReleaseClassifyHandle0(classifyHandle); FbBlock(out); return; }
    /* Every successful writable acquisition is paired with Apply, including
     * identity/family/coexistence rejection below. No early returns here. */
    if (request->previousVersion && request->previousVersion->localRedirectHandle) {
        /* Other redirector's history is not a trusted process/endpoint
         * handoff and must not be promoted to DIRECT. */
        ExFreePoolWithTag(context, FB_POOL_TAG);
        FbBlock(out);
    } else if (v4 && request->remoteAddressAndPort.ss_family == AF_INET) {
        SOCKADDR_IN* target = (SOCKADDR_IN*)&request->remoteAddressAndPort;
        context->address_family = AF_INET; context->destination_port_be = target->sin_port;
        RtlCopyMemory(context->destination_address, &target->sin_addr, 4);
        if (!FbIssueOriginalReceipt(context, ownerPid)) {
            ExFreePoolWithTag(context, FB_POOL_TAG); FbBlock(out);
        } else {
        RtlZeroMemory(&request->remoteAddressAndPort, sizeof(request->remoteAddressAndPort));
        target->sin_family = AF_INET; target->sin_port = config.port_v4_be;
        ((UINT8*)&target->sin_addr)[0] = 127; ((UINT8*)&target->sin_addr)[3] = 1;
        request->localRedirectTargetPID = (DWORD)(ULONG_PTR)ownerPid;
        request->localRedirectHandle = gRedirect;
        request->localRedirectContext = context; request->localRedirectContextSize = sizeof(*context);
        out->actionType = FWP_ACTION_PERMIT; /* context ownership transfers to WFP */
        }
    } else if (!v4 && request->remoteAddressAndPort.ss_family == AF_INET6) {
        SOCKADDR_IN6* target = (SOCKADDR_IN6*)&request->remoteAddressAndPort;
        context->address_family = AF_INET6; context->destination_port_be = target->sin6_port;
        context->ipv6_scope_id = target->sin6_scope_id;
        RtlCopyMemory(context->destination_address, &target->sin6_addr, 16);
        if (!FbIssueOriginalReceipt(context, ownerPid)) {
            ExFreePoolWithTag(context, FB_POOL_TAG); FbBlock(out);
        } else {
        RtlZeroMemory(&request->remoteAddressAndPort, sizeof(request->remoteAddressAndPort));
        target->sin6_family = AF_INET6; target->sin6_port = config.port_v6_be;
        ((UINT8*)&target->sin6_addr)[15] = 1;
        request->localRedirectTargetPID = (DWORD)(ULONG_PTR)ownerPid;
        request->localRedirectHandle = gRedirect;
        request->localRedirectContext = context; request->localRedirectContextSize = sizeof(*context);
        out->actionType = FWP_ACTION_PERMIT;
        }
    } else { ExFreePoolWithTag(context, FB_POOL_TAG); FbBlock(out); }
    /* AcquireWritable cleared ACTION_WRITE. Restore soft permit arbitration
     * unless the filter explicitly requested a hard permit. */
    if (out->actionType == FWP_ACTION_PERMIT && !(filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT))
        out->rights |= FWPS_RIGHT_ACTION_WRITE;
    /* This WDK API returns VOID: the OS, not user supplied return bytes,
     * decides if the redirection took effect. Our issued receipt is NOT an
     * authorization until a later OS ALE_AUTH_CONNECT indication supplies
     * the matching redirected-loopback metadata and consumes it once.
     * No initial AUTH -> no permit. Unmatched tickets occupy bounded storage.
     */
    FwpsApplyModifiedLayerData0(classifyHandle, request, 0);
    FwpsReleaseClassifyHandle0(classifyHandle);
}
static NTSTATUS NTAPI FbNotify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER1* filter) {
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter); return STATUS_SUCCESS;
}
/*
 * Interpret only the kernel-owned v3 context layout returned by WSAIoctl.
 * The exclusive elevated helper supplies this context. The claim can succeed
 * ONLY after a real ALE_AUTH_CONNECT consumed an OS-origin ticket.
 * This IOCTL does not independently prove which socket object was accepted.
 */
static BOOLEAN FbValidateClaim(const FbWfpClaim* claim, HANDLE broker,
                               FbAuthOrigin* output) {
    const FbRedirectContext* context;
    FbAuthOrigin ticket = {0};
    unsigned i;
    if (!claim || !output || !broker ||
        claim->size != sizeof(FbWfpClaim) || claim->version != FB_WFP_ABI)
        return FALSE;
    context = &claim->context;
    if (context->magic != FB_REDIRECT_MAGIC ||
        context->version != FB_REDIRECT_VERSION ||
        context->size != sizeof(FbRedirectContext) ||
        context->original_process_id == (FbUint64)(ULONG_PTR)broker ||
        context->ipv6_scope_id != 0 ||
        !context->process_path_chars ||
        context->process_path_chars >= FB_PROCESS_PATH_CHARS)
        return FALSE;
    for (i = 0; i < sizeof(context->reserved); ++i)
        if (context->reserved[i] != 0) return FALSE;
    for (i = 0; i < FB_PROCESS_PATH_CHARS; ++i) {
        if (i < context->process_path_chars) {
            if (context->process_path[i] < 32) return FALSE;
        } else if (context->process_path[i] != 0) return FALSE;
    }
    ticket.pid = context->original_process_id;
    ticket.creation_100ns = context->original_process_creation_100ns;
    ticket.process_start_key = context->original_process_start_key;
    ticket.endpoint = context->original_transport_endpoint;
    ticket.flow_id = context->flow_id;
    ticket.broker_pid = HandleToULong(broker);
    ticket.family = context->address_family == AF_INET ? 4 :
                    context->address_family == AF_INET6 ? 6 : 0;
    ticket.port_be = context->destination_port_be;
    RtlCopyMemory(ticket.original_ip, context->destination_address, 16);
    if (!FbAuthOriginValid(&ticket)) return FALSE;
    *output = ticket;
    return TRUE;
}
static NTSTATUS FbDispatch(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    KIRQL irql;
    UNREFERENCED_PARAMETER(device);
    KeAcquireSpinLock(&gLock, &irql);
    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        if (gOwner) status = STATUS_SHARING_VIOLATION;
        else { gOwner = stack->FileObject; gOwnerPid = IoGetRequestorProcessId(irp) ? ULongToHandle(IoGetRequestorProcessId(irp)) : NULL; status = gOwnerPid ? STATUS_SUCCESS : STATUS_ACCESS_DENIED; if (!gOwnerPid) gOwner = NULL; }
        break;
    case IRP_MJ_CLEANUP:
        if (gOwner == stack->FileObject) { gEnabled = FALSE; gAuthBook.lost = 1; gOwner = NULL; gOwnerPid = NULL; RtlZeroMemory(&gConfig, sizeof(gConfig)); }
        status = STATUS_SUCCESS; break;
    case IRP_MJ_CLOSE: status = STATUS_SUCCESS; break;
    case IRP_MJ_DEVICE_CONTROL:
        if (gOwner != stack->FileObject || gOwnerPid != ULongToHandle(IoGetRequestorProcessId(irp))) { status = STATUS_ACCESS_DENIED; break; }
        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case FB_IOCTL_CONFIGURE:
            if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(FbWfpConfig)) { status = STATUS_INFO_LENGTH_MISMATCH; break; }
            { FbWfpConfig* c = irp->AssociatedIrp.SystemBuffer;
              if (c->size != sizeof(*c) || c->version != FB_WFP_ABI || c->reserved || !c->port_v4_be || !c->port_v6_be) { status = STATUS_INVALID_PARAMETER; break; }
              if (gEpochTable.lost || gAuthBook.lost || !gEpochNotifierRegistered) { status = STATUS_DEVICE_NOT_READY; break; }
              gConfig = *c; gEnabled = TRUE; status = STATUS_SUCCESS; }
            break;
        case FB_IOCTL_CLAIM:
            if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(FbWfpClaim) ||
                irp->AssociatedIrp.SystemBuffer == NULL) {
                status = STATUS_INFO_LENGTH_MISMATCH; break;
            }
            {
                FbAuthOrigin requested = {0};
                FbEpochRecord live = {0};
                const FbWfpClaim* received = (const FbWfpClaim*)irp->AssociatedIrp.SystemBuffer;
                if (!FbValidateClaim(received, gOwnerPid, &requested)) {
                    status = STATUS_INVALID_PARAMETER; break;
                }
                /* gLock already held by dispatcher. An unchanged owner PID
                 * plus a terminal AUTH book claim is not a copy of a
                 * transient TCP/IP 5-tuple lookup. */
                if (!gEnabled || !gEpochNotifierRegistered ||
                    gEpochTable.lost || gAuthBook.lost) {
                    status = STATUS_DEVICE_NOT_READY; break;
                }
                if (!FbEpochLookup(&gEpochTable, requested.pid, &live) ||
                    live.creation_100ns != requested.creation_100ns ||
                    live.start_key != requested.process_start_key ||
                    !FbAuthClaim(&gAuthBook, &requested)) {
                    status = STATUS_ACCESS_DENIED; break;
                }
                status = STATUS_SUCCESS;
            }
            break;
        case FB_IOCTL_DISABLE: gEnabled = FALSE; gAuthBook.lost = 1; status = STATUS_SUCCESS; break;
        case FB_IOCTL_QUERY:
            if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(FbWfpStatus)) { status = STATUS_BUFFER_TOO_SMALL; break; }
            { FbWfpStatus* s = irp->AssociatedIrp.SystemBuffer; s->size = sizeof(*s); s->version = FB_WFP_ABI; s->enabled = gEnabled; s->service_pid = HandleToULong(gOwnerPid); information = sizeof(*s); status = STATUS_SUCCESS; }
            break;
        }
    }
    KeReleaseSpinLock(&gLock, irql);
    irp->IoStatus.Status = status; irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return status;
}
static void FbUnload(PDRIVER_OBJECT driver) {
    KIRQL irql;
    UNREFERENCED_PARAMETER(driver);
    KeAcquireSpinLock(&gLock, &irql); gEnabled = FALSE; KeReleaseSpinLock(&gLock, irql);
    if (gEpochNotifierRegistered) {
        (void)PsSetCreateProcessNotifyRoutineEx(FbProcessNotify, TRUE);
        gEpochNotifierRegistered = FALSE;
    }
    /* Unregister waits for active inline classifications before destroying the
     * redirect handle. There are no flow contexts/pended classify operations. */
    if (gAuthCallout6) FwpsCalloutUnregisterById0(gAuthCallout6);
    if (gAuthCallout4) FwpsCalloutUnregisterById0(gAuthCallout4);
    if (gCallout6) FwpsCalloutUnregisterById0(gCallout6);
    if (gCallout4) FwpsCalloutUnregisterById0(gCallout4);
    if (gRedirect) FwpsRedirectHandleDestroy0(gRedirect);
    if (gLinkCreated) IoDeleteSymbolicLink(&gLink);
    if (gDevice) IoDeleteDevice(gDevice);
}
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\FlowBridgeWfp");
    UNICODE_STRING acl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    FWPS_CALLOUT1 callout = {0};
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registryPath);
    KeInitializeSpinLock(&gLock);
    RtlZeroMemory(&gEpochTable, sizeof(gEpochTable));
    RtlZeroMemory(&gAuthBook, sizeof(gAuthBook));
    driver->DriverUnload = FbUnload;
    driver->MajorFunction[IRP_MJ_CREATE] = FbDispatch;
    driver->MajorFunction[IRP_MJ_CLEANUP] = FbDispatch;
    driver->MajorFunction[IRP_MJ_CLOSE] = FbDispatch;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FbDispatch;
    status = IoCreateDeviceSecure(driver, 0, &name, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, TRUE, &acl, &FB_WFP_DEVICE_CLASS, &gDevice);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&gLink, &name);
    if (!NT_SUCCESS(status)) goto failure;
    gLinkCreated = TRUE;
    status = FwpsRedirectHandleCreate0(&FB_WFP_PROVIDER, 0, &gRedirect);
    if (!NT_SUCCESS(status)) goto failure;
    callout.classifyFn = FbClassify; callout.notifyFn = FbNotify;
    callout.calloutKey = FB_WFP_CALLOUT4;
    status = FwpsCalloutRegister1(gDevice, &callout, &gCallout4);
    if (!NT_SUCCESS(status)) goto failure;
    callout.calloutKey = FB_WFP_CALLOUT6;
    status = FwpsCalloutRegister1(gDevice, &callout, &gCallout6);
    if (!NT_SUCCESS(status)) goto failure;
    /* AUTH_CONNECT is a separate terminating decision boundary. Do not
     * confuse a successful REDIRECT callback with AUTH or accepted socket. */
    callout.classifyFn = FbAuthClassify;
    callout.calloutKey = FB_WFP_AUTH_CALLOUT4;
    status = FwpsCalloutRegister1(gDevice, &callout, &gAuthCallout4);
    if (!NT_SUCCESS(status)) goto failure;
    callout.calloutKey = FB_WFP_AUTH_CALLOUT6;
    status = FwpsCalloutRegister1(gDevice, &callout, &gAuthCallout6);
    if (!NT_SUCCESS(status)) goto failure;
    status = PsSetCreateProcessNotifyRoutineEx(FbProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) goto failure;
    gEpochNotifierRegistered = TRUE;
    /* No backfill of pre-existing process IDs: launch selected EXEs AFTER
     * the signed driver and process notifier are active, or block. */
    gDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
failure:
    FbUnload(driver); return status;
}
