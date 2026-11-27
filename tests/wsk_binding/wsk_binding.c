#include "wsk_binding.h"
#include <mstcpip.h>
#include "claim.h"
#include "lifecycle.h"

#define FB_WSK_POOL_TAG 'bWbF'
#define FB_WSK_OWNER_POOL_TAG 'oWbF'
#define FB_WSK_RECORD_CAP 4096u
#define FB_WSK_WAIT_BUDGET_100NS (3ULL * 10 * 1000 * 1000)

C_ASSERT(AF_INET == FB_WSK_AF_INET);
C_ASSERT(AF_INET6 == FB_WSK_AF_INET6);
C_ASSERT(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES);

struct FbWskOwner {
    PKSPIN_LOCK authority_lock;
    FbWskGate gate;
    FbWskClaimPolicy policy;
    FbAuthBook history;
    FbWskListenerEpoch target;
    FbEpochRecord broker;
    PEPROCESS listener_process;
    SOCKADDR_STORAGE local;
    WSK_REGISTRATION registration;
    WSK_PROVIDER_NPI provider;
    PWSK_SOCKET listener;
    PIRP request;
    KEVENT finished;
    FbWskOwnerBarrier* join_users;
    FbWskOwnerBarrier* wait_callbacks;
    PVOID barrier_context;
    FbWskOwnerProgress progress;
    NTSTATUS listener_close_status;
    BOOLEAN started;
    BOOLEAN ready;
    BOOLEAN registered;
    BOOLEAN captured;
};

static const UCHAR FbWskLoopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const WSK_CLIENT_DISPATCH FbWskClientDispatch = {MAKE_WSK_VERSION(1, 0), 0, NULL};

struct FbWskBoundConnection {
    PWSK_SOCKET accepted;
    SIZE_T records_size;
    FbRedirectContext context;
    UCHAR records[FB_WSK_RECORD_CAP];
};

struct FbWskDrain {
    FbWskBoundConnection bound;
    FbWskOwner* owner;
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

static void FbWskPrepareRequest(PIRP request, PKEVENT finished)
{
    IoReuseIrp(request, STATUS_UNSUCCESSFUL);
    KeClearEvent(finished);
    IoSetCompletionRoutine(request, FbWskComplete, finished, TRUE, TRUE, TRUE);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskCreateOwner(
    PEPROCESS listener_process, ULONG64 generation, ADDRESS_FAMILY family,
    USHORT port_be, PKSPIN_LOCK authority_lock, FbEpochTable* epochs,
    FbWskOwnerBarrier* join_users, FbWskOwnerBarrier* wait_callbacks,
    PVOID barrier_context, FbWskOwner** result)
{
    FbWskOwner* owner;
    ULONG_PTR pid;

    if (result == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    *result = NULL;
    if (listener_process == NULL || authority_lock == NULL || epochs == NULL ||
        join_users == NULL || wait_callbacks == NULL || !generation || !port_be ||
        (family != AF_INET && family != AF_INET6))
        return STATUS_INVALID_PARAMETER;
    pid = (ULONG_PTR)PsGetProcessId(listener_process);
    if (!pid || pid > MAXULONG)
        return STATUS_INVALID_PARAMETER;

    owner = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*owner), FB_WSK_OWNER_POOL_TAG);
    if (owner == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    owner->request = IoAllocateIrp(1, FALSE);
    if (owner->request == NULL) {
        ExFreePoolWithTag(owner, FB_WSK_OWNER_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeInitializeEvent(&owner->finished, NotificationEvent, FALSE);
    ObReferenceObject(listener_process);
    owner->listener_process = listener_process;
    owner->authority_lock = authority_lock;
    owner->broker.pid = pid;
    owner->broker.creation_100ns = (FbUint64)PsGetProcessCreateTimeQuadPart(listener_process);
    owner->broker.start_key = (FbUint64)PsGetProcessStartKey(listener_process);
    owner->broker.process_token = (FbUint64)(ULONG_PTR)listener_process;
    owner->target.generation = generation;
    owner->target.broker_pid = (FbUint32)pid;
    owner->target.address_family = family;
    owner->target.port_be = port_be;
    owner->policy.epochs = epochs;
    owner->policy.auth = &owner->history;
    owner->policy.generation = generation;
    owner->policy.broker_pid = (FbUint32)pid;
    owner->join_users = join_users;
    owner->wait_callbacks = wait_callbacks;
    owner->barrier_context = barrier_context;
    owner->progress = FbWskOwnerWaitingForUsers;
    if (family == AF_INET) {
        SOCKADDR_IN* address = (SOCKADDR_IN*)&owner->local;
        address->sin_family = family;
        address->sin_port = port_be;
        address->sin_addr.S_un.S_un_b.s_b1 = 127;
        address->sin_addr.S_un.S_un_b.s_b4 = 1;
    } else {
        SOCKADDR_IN6* address = (SOCKADDR_IN6*)&owner->local;
        address->sin6_family = family;
        address->sin6_port = port_be;
        RtlCopyMemory(&address->sin6_addr, FbWskLoopback6, sizeof(FbWskLoopback6));
    }
    *result = owner;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS FbWskWaitForStartup(FbWskOwner* owner)
{
    (void)KeWaitForSingleObject(&owner->finished, Executive, KernelMode, FALSE, NULL);
    return owner->request->IoStatus.Status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskStartOwner(FbWskOwner* owner)
{
    WSK_CLIENT_NPI client = {NULL, &FbWskClientDispatch};
    const WSK_PROVIDER_LISTEN_DISPATCH* dispatch;
    NTSTATUS status;

    if (owner == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    if (owner->started || owner->gate.stopping)
        return STATUS_INVALID_DEVICE_STATE;
    owner->started = TRUE;

    status = WskRegister(&client, &owner->registration);
    if (status != STATUS_SUCCESS)
        return status;
    owner->registered = TRUE;
    status = WskCaptureProviderNPI(&owner->registration, WSK_NO_WAIT, &owner->provider);
    if (status != STATUS_SUCCESS)
        return status;
    owner->captured = TRUE;

    FbWskPrepareRequest(owner->request, &owner->finished);
    (void)owner->provider.Dispatch->WskSocket(
        owner->provider.Client, owner->target.address_family, SOCK_STREAM, IPPROTO_TCP,
        WSK_FLAG_LISTEN_SOCKET, NULL, NULL, owner->listener_process, NULL, NULL, owner->request);
    status = FbWskWaitForStartup(owner);
    if (status != STATUS_SUCCESS)
        return status;
    owner->listener = (PWSK_SOCKET)owner->request->IoStatus.Information;
    if (owner->listener == NULL)
        return STATUS_INTERNAL_ERROR;

    dispatch = owner->listener->Dispatch;
    FbWskPrepareRequest(owner->request, &owner->finished);
    (void)dispatch->WskBind(owner->listener, (PSOCKADDR)&owner->local, 0, owner->request);
    status = FbWskWaitForStartup(owner);
    owner->ready = status == STATUS_SUCCESS;
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskArmOwner(FbWskOwner* owner)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    KIRQL irql;

    if (owner == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(owner->authority_lock, &irql);
    if (owner->ready && !owner->gate.stopping && !owner->policy.armed &&
        FbWskBrokerEpochIsLive(owner->policy.epochs, &owner->broker)) {
        owner->policy.armed = 1;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(owner->authority_lock, irql);
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS FbWskLockOwnerAuthority(
    FbWskOwner* owner, PKIRQL previous_irql, const FbWskClaimPolicy** policy,
    const FbWskListenerEpoch** target)
{
    if (owner == NULL || previous_irql == NULL || policy == NULL || target == NULL)
        return STATUS_INVALID_PARAMETER;
    *policy = NULL;
    *target = NULL;
    KeAcquireSpinLock(owner->authority_lock, previous_irql);
    if (!owner->policy.armed || !FbWskBrokerEpochIsLive(owner->policy.epochs, &owner->broker)) {
        KeReleaseSpinLock(owner->authority_lock, *previous_irql);
        return STATUS_ACCESS_DENIED;
    }
    *policy = &owner->policy;
    *target = &owner->target;
    return STATUS_SUCCESS;
}

_IRQL_requires_(DISPATCH_LEVEL)
void FbWskUnlockOwnerAuthority(FbWskOwner* owner, KIRQL previous_irql)
{
    KeReleaseSpinLock(owner->authority_lock, previous_irql);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskStopOwner(FbWskOwner* owner, PULONG outstanding)
{
    ULONG count;
    KIRQL irql;

    if (owner == NULL || outstanding == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(owner->authority_lock, &irql);
    count = FbWskDisarmOwner(&owner->gate, &owner->policy.armed);
    KeReleaseSpinLock(owner->authority_lock, irql);
    *outstanding = count;
    return count == 0 ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskAdvanceOwnerRundown(FbWskOwner** handle)
{
    FbWskOwner* owner;
    FbWskGate gate;
    KIRQL irql;
    NTSTATUS status;
    LARGE_INTEGER no_wait = {0};

    if (handle == NULL || *handle == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    owner = *handle;
    KeAcquireSpinLock(owner->authority_lock, &irql);
    gate = owner->gate;
    KeReleaseSpinLock(owner->authority_lock, irql);

    for (;;) {
        switch (FbWskNextOwnerStep(&gate, owner->progress, owner->listener != NULL)) {
        case FbWskOwnerNeedsStop:
            return STATUS_INVALID_DEVICE_STATE;
        case FbWskOwnerNeedsBindingDrain:
            return STATUS_DEVICE_BUSY;
        case FbWskOwnerJoinUsers:
            status = owner->join_users(owner->barrier_context);
            if (status != STATUS_SUCCESS)
                return status;
            owner->progress = FbWskOwnerUsersJoined;
            break;
        case FbWskOwnerCloseListener: {
            PWSK_SOCKET listener = owner->listener;
            const WSK_PROVIDER_BASIC_DISPATCH* dispatch = listener->Dispatch;
            FbWskPrepareRequest(owner->request, &owner->finished);
            owner->listener = NULL;
            owner->progress = FbWskOwnerListenerClosing;
            (void)dispatch->WskCloseSocket(listener, owner->request);
            return STATUS_PENDING;
        }
        case FbWskOwnerCollectListenerClose:
            if (KeWaitForSingleObject(&owner->finished, Executive, KernelMode,
                                      FALSE, &no_wait) != STATUS_SUCCESS)
                return STATUS_PENDING;
            owner->listener_close_status = owner->request->IoStatus.Status;
            owner->progress = owner->listener_close_status == STATUS_SUCCESS
                ? FbWskOwnerListenerClosed : FbWskOwnerListenerCloseFailed;
            break;
        case FbWskOwnerHoldListenerCloseFailure:
            return owner->listener_close_status;
        case FbWskOwnerReleaseProvider:
            if (owner->captured) {
                WskReleaseProviderNPI(&owner->registration);
                owner->captured = FALSE;
            }
            owner->progress = FbWskOwnerProviderReleased;
            break;
        case FbWskOwnerDeregister:
            if (owner->registered) {
                WskDeregister(&owner->registration);
                owner->registered = FALSE;
            }
            owner->progress = FbWskOwnerProviderDeregistered;
            break;
        case FbWskOwnerWaitForCallbacks:
            status = owner->wait_callbacks(owner->barrier_context);
            if (status != STATUS_SUCCESS)
                return status;
            owner->progress = FbWskOwnerCallbacksReturned;
            break;
        case FbWskOwnerFree:
            IoFreeIrp(owner->request);
            ObDereferenceObject(owner->listener_process);
            RtlSecureZeroMemory(owner, sizeof(*owner));
            ExFreePoolWithTag(owner, FB_WSK_OWNER_POOL_TAG);
            *handle = NULL;
            return STATUS_SUCCESS;
        case FbWskOwnerInvalidState:
            return STATUS_INTERNAL_ERROR;
        }
    }
}

static void FbWskLeaveBinding(FbWskOwner* owner)
{
    KIRQL irql;
    KeAcquireSpinLock(owner->authority_lock, &irql);
    FbWskGateLeave(&owner->gate);
    KeReleaseSpinLock(owner->authority_lock, irql);
}

static void FbWskPrepare(FbWskDrain* connection, FbWskOperation operation)
{
    FbWskPrepareRequest(connection->request, &connection->finished);
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
               RtlEqualMemory(&address->sin6_addr, FbWskLoopback6, sizeof(FbWskLoopback6));
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
    FbWskOwner* owner = connection->owner;
    *handle = NULL;
    IoFreeIrp(connection->request);
    RtlSecureZeroMemory(connection, sizeof(*connection));
    ExFreePoolWithTag(connection, FB_WSK_POOL_TAG);
    FbWskLeaveBinding(owner);
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
    FbWskOwner* owner, FbWskBoundConnection** result, FbWskDrain** drain)
{
    const WSK_PROVIDER_LISTEN_DISPATCH* listen_dispatch;
    const WSK_PROVIDER_BASIC_DISPATCH* accepted_dispatch;
    PWSK_SOCKET listener;
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
    if (owner == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(owner->authority_lock, &irql);
    admitted = FbWskBrokerEpochIsLive(owner->policy.epochs, &owner->broker) &&
               FbWskEnterArmedBinding(&owner->gate, owner->policy.armed);
    KeReleaseSpinLock(owner->authority_lock, irql);
    if (!admitted)
        return STATUS_DEVICE_BUSY;
    listener = owner->listener;

    connection = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*connection), FB_WSK_POOL_TAG);
    if (connection == NULL) {
        FbWskLeaveBinding(owner);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    connection->owner = owner;
    connection->request = IoAllocateIrp(1, FALSE);
    if (connection->request == NULL) {
        ExFreePoolWithTag(connection, FB_WSK_POOL_TAG);
        FbWskLeaveBinding(owner);
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
        !FbWskIsExpectedLoopback(&connection->local, &owner->target)) {
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

    KeAcquireSpinLock(owner->authority_lock, &irql);
    if (KeQueryInterruptTime() - started >= FB_WSK_WAIT_BUDGET_100NS) {
        status = STATUS_IO_TIMEOUT;
    } else {
        status = FbWskBrokerEpochIsLive(owner->policy.epochs, &owner->broker) &&
                 FbWskCommitAcceptedContext(&owner->policy, &owner->target, &connection->bound.context)
            ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }
    KeReleaseSpinLock(owner->authority_lock, irql);
    if (status != STATUS_SUCCESS)
        goto reject;

    *result = &connection->bound;
    return STATUS_SUCCESS;

reject:
    *drain = connection;
    return status;
}
