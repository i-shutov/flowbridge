#include "wsk_binding.h"
#include <mstcpip.h>
#include "claim.h"

#define FB_WSK_POOL_TAG 'bWbF'
#define FB_WSK_RECORD_CAP 4096u

C_ASSERT(AF_INET == FB_WSK_AF_INET);
C_ASSERT(AF_INET6 == FB_WSK_AF_INET6);
C_ASSERT(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES);

struct FbWskBoundConnection {
    PWSK_SOCKET accepted;
    PIRP request;
    KEVENT finished;
    SIZE_T records_size;
    FbRedirectContext context;
    UCHAR records[FB_WSK_RECORD_CAP];
};

static IO_COMPLETION_ROUTINE FbWskComplete;
static NTSTATUS NTAPI FbWskComplete(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(irp);
    KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static void FbWskPrepare(FbWskBoundConnection* connection)
{
    IoReuseIrp(connection->request, STATUS_UNSUCCESSFUL);
    KeClearEvent(&connection->finished);
    IoSetCompletionRoutine(connection->request, FbWskComplete,
                           &connection->finished, TRUE, TRUE, TRUE);
}

/* WSK completes each IRP even on an immediate return. After a timed wait the
 * IRP and buffers remain owned by WSK until cancellation is fully drained. */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN FbWskWait(FbWskBoundConnection* connection, BOOLEAN timed)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -3LL * 10 * 1000 * 1000;
    if (KeWaitForSingleObject(&connection->finished, Executive, KernelMode,
                              FALSE, timed ? &timeout : NULL) == STATUS_TIMEOUT) {
        (void)IoCancelIrp(connection->request);
        (void)KeWaitForSingleObject(&connection->finished, Executive, KernelMode,
                                    FALSE, NULL);
        return FALSE;
    }
    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS FbWskQuery(
    FbWskBoundConnection* connection, const WSK_PROVIDER_BASIC_DISPATCH* dispatch,
    ULONG code, SIZE_T capacity, PVOID output, SIZE_T* length)
{
    FbWskPrepare(connection);
    (void)dispatch->WskControlSocket(connection->accepted, WskIoctl, code, 0,
                                    0, NULL, capacity, output, NULL,
                                    connection->request);
    if (!FbWskWait(connection, TRUE))
        return STATUS_IO_TIMEOUT;

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
NTSTATUS FbWskReleaseBound(FbWskBoundConnection* connection)
{
    NTSTATUS status = STATUS_SUCCESS;
    if (connection == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;

    if (connection->accepted != NULL) {
        const WSK_PROVIDER_BASIC_DISPATCH* dispatch = connection->accepted->Dispatch;
        FbWskPrepare(connection);
        (void)dispatch->WskCloseSocket(connection->accepted, connection->request);
        (void)FbWskWait(connection, FALSE);
        status = connection->request->IoStatus.Status;
    }

    IoFreeIrp(connection->request);
    RtlSecureZeroMemory(connection, sizeof(*connection));
    ExFreePoolWithTag(connection, FB_WSK_POOL_TAG);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskAcceptBound(
    PWSK_SOCKET listener, const FbWskListenerEpoch* listener_epoch,
    PKSPIN_LOCK policy_lock, FbWskClaimPolicy* policy_state,
    FbWskBoundConnection** result)
{
    const WSK_PROVIDER_LISTEN_DISPATCH* listen_dispatch;
    const WSK_PROVIDER_BASIC_DISPATCH* accepted_dispatch;
    FbWskBoundConnection* connection;
    SOCKADDR_STORAGE local = {0};
    SIZE_T context_size = 0;
    BOOLEAN completed;
    NTSTATUS status;
    KIRQL irql;

    if (result == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    *result = NULL;
    if (listener == NULL || listener_epoch == NULL || policy_lock == NULL ||
        policy_state == NULL)
        return STATUS_INVALID_PARAMETER;

    connection = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*connection), FB_WSK_POOL_TAG);
    if (connection == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    connection->request = IoAllocateIrp(1, FALSE);
    if (connection->request == NULL) {
        ExFreePoolWithTag(connection, FB_WSK_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&connection->finished, NotificationEvent, FALSE);
    listen_dispatch = listener->Dispatch;
    FbWskPrepare(connection);
    (void)listen_dispatch->WskAccept(listener, 0, NULL, NULL,
                                    (PSOCKADDR)&local, NULL, connection->request);
    completed = FbWskWait(connection, TRUE);
    status = connection->request->IoStatus.Status;
    if (status == STATUS_SUCCESS)
        connection->accepted = (PWSK_SOCKET)connection->request->IoStatus.Information;
    if (!completed) {
        status = STATUS_IO_TIMEOUT;
        goto reject;
    }
    if (status != STATUS_SUCCESS)
        goto reject;

    if (connection->accepted == NULL || !FbWskIsExpectedLoopback(&local, listener_epoch)) {
        status = STATUS_ACCESS_DENIED;
        goto reject;
    }

    /* Both queries receive the only accepted object in this transaction.
     * Irp->IoStatus.Information contains bytes here, not an object pointer.
     * Nothing in this function accepts redirect bytes from its caller. */
    accepted_dispatch = connection->accepted->Dispatch;
    status = FbWskQuery(connection, accepted_dispatch, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
                        sizeof(connection->context), &connection->context, &context_size);
    if (status != STATUS_SUCCESS)
        goto reject;
    if (context_size != sizeof(connection->context)) {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto reject;
    }

    status = FbWskQuery(connection, accepted_dispatch, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
                        sizeof(connection->records), connection->records, &connection->records_size);
    if (status != STATUS_SUCCESS)
        goto reject;
    if (!connection->records_size || connection->records_size > sizeof(connection->records)) {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto reject;
    }

    KeAcquireSpinLock(policy_lock, &irql);
    status = FbWskCommitAcceptedContext(policy_state, listener_epoch, &connection->context)
        ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    KeReleaseSpinLock(policy_lock, irql);
    if (status != STATUS_SUCCESS)
        goto reject;

    *result = connection;
    return STATUS_SUCCESS;

reject:
    (void)FbWskReleaseBound(connection);
    return status;
}
