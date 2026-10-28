/* Original FlowBridge WFP callout. Build with WDK, not a user-mode SDK.
 * Inline classify only: no pending packets, work items, or user pointers. */
#include <ntddk.h>
#include <wdmsec.h>
#include <fwpsk.h>
#include <ws2ipdef.h>
#include "../control.h"
#include "../redirect_context.h"
#define FB_POOL_TAG 'rBbF'
C_ASSERT(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES);
static PDEVICE_OBJECT gDevice;
static HANDLE gRedirect;
static UINT32 gCallout4, gCallout6;
static KSPIN_LOCK gLock;
static PFILE_OBJECT gOwner;
static HANDLE gOwnerPid;
static FbWfpConfig gConfig;
static BOOLEAN gEnabled;
static BOOLEAN gLinkCreated;
static volatile LONG64 gFlowId;
static UNICODE_STRING gLink = RTL_CONSTANT_STRING(L"\\DosDevices\\FlowBridgeWfp");

static void FbBlock(FWPS_CLASSIFY_OUT0* out) {
    out->actionType = FWP_ACTION_BLOCK;
    out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}
static void NTAPI FbClassify(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, void* layerData,
    const void* classifyContext, const FWPS_FILTER1* filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0* out) {
    KIRQL irql;
    FbWfpConfig config;
    HANDLE ownerPid;
    BOOLEAN enabled, v4;
    UINT32 appIndex, protocolIndex;
    FWP_BYTE_BLOB* app;
    SIZE_T chars, i;
    FbRedirectContext* context = NULL;
    FWPS_CONNECT_REQUEST0* request = NULL;
    UINT64 classifyHandle = 0;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    out->actionType = FWP_ACTION_PERMIT; /* soft permit; no firewall override */
    KeAcquireSpinLock(&gLock, &irql);
    enabled = gEnabled; config = gConfig; ownerPid = gOwnerPid;
    KeReleaseSpinLock(&gLock, irql);
    if (!enabled) return;
    v4 = values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4;
    if (!v4 && values->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) return;
    protocolIndex = v4 ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL;
    appIndex = v4 ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID : FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID;
    if (values->incomingValue[protocolIndex].value.uint8 != IPPROTO_TCP) return;
    if (!FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_ID)) { FbBlock(out); return; }
    if (metadata->processId == (UINT64)(ULONG_PTR)ownerPid) return;
    if (FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
        FWPS_CONNECTION_REDIRECT_STATE state = FwpsQueryConnectionRedirectState0(metadata->redirectRecords, gRedirect, NULL);
        /* Respect another redirector. Its target is not the original endpoint.
         * Capture coverage is explicitly reduced in this coexistence case. */
        if (state != FWPS_CONNECTION_NOT_REDIRECTED) return;
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
    RtlCopyMemory(context->process_path, app->data, chars * sizeof(UINT16));
    /* The API takes an opaque non-const pointer although classifyFn receives const. */
    status = FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(context, FB_POOL_TAG); FbBlock(out); return; }
    status = FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0, (PVOID*)&request, out);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(context, FB_POOL_TAG); FwpsReleaseClassifyHandle0(classifyHandle); FbBlock(out); return; }
    /* Every successful writable acquisition is paired with Apply, including
     * identity/family/coexistence rejection below. No early returns here. */
    if (request->previousVersion && request->previousVersion->localRedirectHandle) {
        ExFreePoolWithTag(context, FB_POOL_TAG);
        out->actionType = FWP_ACTION_PERMIT;
    } else if (v4 && request->remoteAddressAndPort.ss_family == AF_INET) {
        SOCKADDR_IN* target = (SOCKADDR_IN*)&request->remoteAddressAndPort;
        context->address_family = AF_INET; context->destination_port_be = target->sin_port;
        RtlCopyMemory(context->destination_address, &target->sin_addr, 4);
        RtlZeroMemory(&request->remoteAddressAndPort, sizeof(request->remoteAddressAndPort));
        target->sin_family = AF_INET; target->sin_port = config.port_v4_be;
        ((UINT8*)&target->sin_addr)[0] = 127; ((UINT8*)&target->sin_addr)[3] = 1;
        request->localRedirectTargetPID = (DWORD)(ULONG_PTR)ownerPid;
        request->localRedirectHandle = gRedirect;
        request->localRedirectContext = context; request->localRedirectContextSize = sizeof(*context);
        out->actionType = FWP_ACTION_PERMIT; /* context ownership transfers to WFP */
    } else if (!v4 && request->remoteAddressAndPort.ss_family == AF_INET6) {
        SOCKADDR_IN6* target = (SOCKADDR_IN6*)&request->remoteAddressAndPort;
        context->address_family = AF_INET6; context->destination_port_be = target->sin6_port;
        context->ipv6_scope_id = target->sin6_scope_id;
        RtlCopyMemory(context->destination_address, &target->sin6_addr, 16);
        RtlZeroMemory(&request->remoteAddressAndPort, sizeof(request->remoteAddressAndPort));
        target->sin6_family = AF_INET6; target->sin6_port = config.port_v6_be;
        ((UINT8*)&target->sin6_addr)[15] = 1;
        request->localRedirectTargetPID = (DWORD)(ULONG_PTR)ownerPid;
        request->localRedirectHandle = gRedirect;
        request->localRedirectContext = context; request->localRedirectContextSize = sizeof(*context);
        out->actionType = FWP_ACTION_PERMIT;
    } else { ExFreePoolWithTag(context, FB_POOL_TAG); FbBlock(out); }
    /* AcquireWritable cleared ACTION_WRITE. Restore soft permit arbitration
     * unless the filter explicitly requested a hard permit. */
    if (out->actionType == FWP_ACTION_PERMIT && !(filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT))
        out->rights |= FWPS_RIGHT_ACTION_WRITE;
    FwpsApplyModifiedLayerData0(classifyHandle, request, 0);
    FwpsReleaseClassifyHandle0(classifyHandle);
}
static NTSTATUS NTAPI FbNotify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER1* filter) {
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter); return STATUS_SUCCESS;
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
        if (gOwner == stack->FileObject) { gEnabled = FALSE; gOwner = NULL; gOwnerPid = NULL; RtlZeroMemory(&gConfig, sizeof(gConfig)); }
        status = STATUS_SUCCESS; break;
    case IRP_MJ_CLOSE: status = STATUS_SUCCESS; break;
    case IRP_MJ_DEVICE_CONTROL:
        if (gOwner != stack->FileObject || gOwnerPid != ULongToHandle(IoGetRequestorProcessId(irp))) { status = STATUS_ACCESS_DENIED; break; }
        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case FB_IOCTL_CONFIGURE:
            if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(FbWfpConfig)) { status = STATUS_INFO_LENGTH_MISMATCH; break; }
            { FbWfpConfig* c = irp->AssociatedIrp.SystemBuffer;
              if (c->size != sizeof(*c) || c->version != FB_WFP_ABI || c->reserved || !c->port_v4_be || !c->port_v6_be) { status = STATUS_INVALID_PARAMETER; break; }
              gConfig = *c; gEnabled = TRUE; status = STATUS_SUCCESS; }
            break;
        case FB_IOCTL_DISABLE: gEnabled = FALSE; status = STATUS_SUCCESS; break;
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
    /* Unregister waits for active inline classifications before destroying the
     * redirect handle. There are no flow contexts/pended classify operations. */
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
    gDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
failure:
    FbUnload(driver); return status;
}
