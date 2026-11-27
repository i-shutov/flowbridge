#include "wsk_binding.h"
#include <mstcpip.h>
#include "claim.h"

#define FB_WSK_POOL_TAG 'bWbF'
#define FB_WSK_RECORD_CAP 4096u
#define FB_WSK_WAIT_BUDGET_100NS (3ULL * 10 * 1000 * 1000)

C_ASSERT(AF_INET == FB_WSK_AF_INET);
C_ASSERT(AF_INET6 == FB_WSK_AF_INET6);
C_ASSERT(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES);

struct FbWskBoundConnection {
    PWSK_SOCKET accepted;
    SIZE_T records_size;
    FbRedirectContext context;
    UCHAR records[FB_WSK_RECORD_CAP];
};

struct FbWskDrain {
    FbWskBoundConnection bound;
    FbWskBindingLifetime* lifetime;
    PIRP request;
    KEVENT finished;
    SOCKADDR_STORAGE local;
    FbWskOperation operation;
    BOOLEAN cancel_requested;
};

static IO_COMPLETION_ROUTINE FbWskComplete;
static NTSTATUS NTAPI FbWskComplete(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(irp);
    /* The owner may reclaim or reuse the request after observing the event. */
    KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

_IRQL_requires_(PASSIVE_LEVEL)
void FbWskInitializeBindingLifetime(FbWskBindingLifetime* lifetime)
{
    KeInitializeSpinLock(&lifetime->lock);
    lifetime->gate.outstanding = 0;
    lifetime->gate.stopping = 0;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskStopBinding(FbWskBindingLifetime* lifetime, PULONG outstanding)
{
    ULONG count;
    KIRQL irql;
    KeAcquireSpinLock(&lifetime->lock, &irql);
    count = FbWskGateStop(&lifetime->gate);
    KeReleaseSpinLock(&lifetime->lock, irql);
    *outstanding = count;
    return count == 0 ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
}

static void FbWskLeaveBinding(FbWskBindingLifetime* lifetime)
{
    KIRQL irql;
    KeAcquireSpinLock(&lifetime->lock, &irql);
    FbWskGateLeave(&lifetime->gate);
    KeReleaseSpinLock(&lifetime->lock, irql);
}

static void FbWskPrepare(FbWskDrain* connection, FbWskOperation operation)
{
    IoReuseIrp(connection->request, STATUS_UNSUCCESSFUL);
    KeClearEvent(&connection->finished);
    IoSetCompletionRoutine(connection->request, FbWskComplete,
                           &connection->finished, TRUE, TRUE, TRUE);
    connection->operation = operation;
    connection->cancel_requested = FALSE;
}

/* WSK completes each IRP even on an immediate return. The timeout leaves
 * everything the provider may still access in the cleanup handle. */
_IRQL_requires_(PASSIVE_LEVEL)
static int FbWskWait(FbWskDrain* connection, ULONG64 started)
{
    LARGE_INTEGER timeout;
    ULONG64 elapsed = KeQueryInterruptTime() - started;
    if (elapsed >= FB_WSK_WAIT_BUDGET_100NS)
        return FALSE;
    timeout.QuadPart = -(LONGLONG)(FB_WSK_WAIT_BUDGET_100NS - elapsed);
    return KeWaitForSingleObject(&connection->finished, Executive, KernelMode,
                                 FALSE, &timeout) == STATUS_SUCCESS &&
           KeQueryInterruptTime() - started < FB_WSK_WAIT_BUDGET_100NS;
}

static NTSTATUS FbWskCollectAcceptedObject(FbWskDrain* connection)
{
    NTSTATUS status = connection->request->IoStatus.Status;
    if (status == STATUS_SUCCESS)
        connection->bound.accepted = (PWSK_SOCKET)connection->request->IoStatus.Information;
    connection->operation = FbWskIdle;
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS FbWskQuery(
    FbWskDrain* connection, const WSK_PROVIDER_BASIC_DISPATCH* dispatch,
    ULONG code, SIZE_T capacity, PVOID output, SIZE_T* length, ULONG64 started)
{
    if (KeQueryInterruptTime() - started >= FB_WSK_WAIT_BUDGET_100NS)
        return STATUS_IO_TIMEOUT;
    FbWskPrepare(connection, FbWskQuerySocket);
    (void)dispatch->WskControlSocket(connection->bound.accepted, WskIoctl, code, 0,
                                    0, NULL, capacity, output, NULL,
                                    connection->request);
    if (!FbWskWait(connection, started))
        return STATUS_IO_TIMEOUT;

    connection->operation = FbWskIdle;
    *length = connection->request->IoStatus.Information;
    return connection->request->IoStatus.Status;
}

static BOOLEAN FbWskIsExpectedLoopback(const SOCKADDR_STORAGE* local,
                                      const FbWskListenerEpoch* epoch)
{
    static const UCHAR loopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (local->ss_family != epoch->address_family || !epoch->port_be)
        return FALSE;
    if (local->ss_family == AF_INET) {
        const SOCKADDR_IN* address = (const SOCKADDR_IN*)local;
        return address->sin_port == epoch->port_be &&
               address->sin_addr.S_un.S_un_b.s_b1 == 127 &&
               address->sin_addr.S_un.S_un_b.s_b2 == 0 &&
               address->sin_addr.S_un.S_un_b.s_b3 == 0 &&
               address->sin_addr.S_un.S_un_b.s_b4 == 1;
    }
    if (local->ss_family == AF_INET6) {
        const SOCKADDR_IN6* address = (const SOCKADDR_IN6*)local;
        return address->sin6_port == epoch->port_be && address->sin6_scope_id == 0 &&
               RtlEqualMemory(&address->sin6_addr, loopback6, sizeof(loopback6));
    }
    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
FbWskDrain* FbWskReleaseBound(FbWskBoundConnection** connection)
{
    FbWskDrain* drain;
    if (connection == NULL || *connection == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return NULL;
    drain = CONTAINING_RECORD(*connection, FbWskDrain, bound);
    *connection = NULL;
    return drain;
}

static NTSTATUS FbWskFreeDrain(FbWskDrain** handle)
{
    FbWskDrain* connection = *handle;
    FbWskBindingLifetime* lifetime = connection->lifetime;
    *handle = NULL;
    IoFreeIrp(connection->request);
    RtlSecureZeroMemory(connection, sizeof(*connection));
    ExFreePoolWithTag(connection, FB_WSK_POOL_TAG);
    FbWskLeaveBinding(lifetime);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskDrainBound(FbWskDrain** handle)
{
    FbWskDrain* connection;
    const WSK_PROVIDER_BASIC_DISPATCH* dispatch;
    PWSK_SOCKET socket;
    LARGE_INTEGER no_wait = {0};
    int complete;
    NTSTATUS close_status = STATUS_PENDING;

    if (handle == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    connection = *handle;
    if (connection == NULL)
        return STATUS_SUCCESS;

    complete = connection->operation != FbWskIdle &&
        KeWaitForSingleObject(&connection->finished, Executive, KernelMode,
                              FALSE, &no_wait) == STATUS_SUCCESS;
    if (complete && connection->operation == FbWskClose)
        close_status = connection->request->IoStatus.Status;
    switch (FbWskNextDrainStep(connection->operation, complete, connection->cancel_requested,
                               connection->bound.accepted != NULL,
                               close_status == STATUS_SUCCESS)) {
    case FbWskWaitForCompletion:
        return STATUS_PENDING;
    case FbWskRequestCancel:
        /* This owner holds the IRP across cancellation, even if it completes inline. */
        connection->cancel_requested = TRUE;
        (void)IoCancelIrp(connection->request);
        return STATUS_PENDING;
    case FbWskCollectAccept:
        /* Completion can succeed even when cancellation was requested. */
        (void)FbWskCollectAcceptedObject(connection);
        return STATUS_PENDING;
    case FbWskDiscardQuery:
        connection->operation = FbWskIdle;
        return STATUS_PENDING;
    case FbWskStartClose:
        socket = connection->bound.accepted;
        dispatch = socket->Dispatch;
        FbWskPrepare(connection, FbWskClose);
        connection->bound.accepted = NULL;
        (void)dispatch->WskCloseSocket(socket, connection->request);
        return STATUS_PENDING;
    case FbWskHoldCloseFailure:
        /* WSK forbids further calls on the socket after close was issued.
         * Leave any failed close observable and hold the lifetime gate. */
        return close_status;
    case FbWskFree:
        return FbWskFreeDrain(handle);
    }

    return STATUS_INTERNAL_ERROR;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskAcceptBound(
    FbWskBindingLifetime* lifetime, PWSK_SOCKET listener, const FbWskListenerEpoch* listener_epoch,
    PKSPIN_LOCK policy_lock, FbWskClaimPolicy* policy_state,
    FbWskBoundConnection** result, FbWskDrain** drain)
{
    const WSK_PROVIDER_LISTEN_DISPATCH* listen_dispatch;
    const WSK_PROVIDER_BASIC_DISPATCH* accepted_dispatch;
    FbWskDrain* connection;
    SIZE_T context_size = 0;
    ULONG64 started = KeQueryInterruptTime();
    int admitted;
    NTSTATUS status;
    KIRQL irql;

    if (result == NULL || drain == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    *result = NULL;
    *drain = NULL;
    if (lifetime == NULL || listener == NULL || listener_epoch == NULL ||
        policy_lock == NULL || policy_state == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&lifetime->lock, &irql);
    admitted = FbWskGateEnter(&lifetime->gate);
    KeReleaseSpinLock(&lifetime->lock, irql);
    if (!admitted)
        return STATUS_DEVICE_BUSY;

    connection = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*connection), FB_WSK_POOL_TAG);
    if (connection == NULL) {
        FbWskLeaveBinding(lifetime);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    connection->lifetime = lifetime;
    connection->request = IoAllocateIrp(1, FALSE);
    if (connection->request == NULL) {
        ExFreePoolWithTag(connection, FB_WSK_POOL_TAG);
        FbWskLeaveBinding(lifetime);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&connection->finished, NotificationEvent, FALSE);
    if (KeQueryInterruptTime() - started >= FB_WSK_WAIT_BUDGET_100NS) {
        status = STATUS_IO_TIMEOUT;
        goto reject;
    }
    listen_dispatch = listener->Dispatch;
    FbWskPrepare(connection, FbWskAccept);
    (void)listen_dispatch->WskAccept(listener, 0, NULL, NULL,
                                    (PSOCKADDR)&connection->local, NULL, connection->request);
    if (!FbWskWait(connection, started)) {
        status = STATUS_IO_TIMEOUT;
        goto reject;
    }
    status = FbWskCollectAcceptedObject(connection);
    if (status != STATUS_SUCCESS)
        goto reject;

    if (connection->bound.accepted == NULL ||
        !FbWskIsExpectedLoopback(&connection->local, listener_epoch)) {
        status = STATUS_ACCESS_DENIED;
        goto reject;
    }

    /* Both queries receive the only accepted object in this transaction.
     * Irp->IoStatus.Information contains bytes here, not an object pointer.
     * Nothing in this function accepts redirect bytes from its caller. */
    accepted_dispatch = connection->bound.accepted->Dispatch;
    status = FbWskQuery(connection, accepted_dispatch, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
                        sizeof(connection->bound.context), &connection->bound.context,
                        &context_size, started);
    if (status != STATUS_SUCCESS)
        goto reject;
    if (context_size != sizeof(connection->bound.context)) {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto reject;
    }

    status = FbWskQuery(connection, accepted_dispatch, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
                        sizeof(connection->bound.records), connection->bound.records,
                        &connection->bound.records_size, started);
    if (status != STATUS_SUCCESS)
        goto reject;
    if (!connection->bound.records_size ||
        connection->bound.records_size > sizeof(connection->bound.records)) {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto reject;
    }

    KeAcquireSpinLock(policy_lock, &irql);
    if (KeQueryInterruptTime() - started >= FB_WSK_WAIT_BUDGET_100NS) {
        status = STATUS_IO_TIMEOUT;
    } else {
        status = FbWskCommitAcceptedContext(policy_state, listener_epoch, &connection->bound.context)
            ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }
    KeReleaseSpinLock(policy_lock, irql);
    if (status != STATUS_SUCCESS)
        goto reject;

    *result = &connection->bound;
    return STATUS_SUCCESS;

reject:
    *drain = connection;
    return status;
}
