#ifndef FLOWBRIDGE_WSK_BINDING_H
#define FLOWBRIDGE_WSK_BINDING_H

#include <ntddk.h>
#include <wsk.h>

/* Kernel-only prototype. No dispatch, ioctl, listener creation or consumer.
 * policy_state is a shared per-arm authority protected by policy_lock.
 * listener_epoch is the immutable identity of the supplied WSK listener.
 * Both and the provider NPI must outlive the returned bound connection.
 * The caller holds listener rundown until the function returns and must
 * name the component that owns policy, listener and provider rundown before
 * wiring this seam to a worker. Do not give it any user-supplied pointers.
 */
struct FbWskClaimPolicy;
struct FbWskListenerEpoch;
typedef struct FbWskBoundConnection FbWskBoundConnection;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskAcceptBound(
    PWSK_SOCKET listener,
    const struct FbWskListenerEpoch* listener_epoch,
    PKSPIN_LOCK policy_lock,
    struct FbWskClaimPolicy* policy_state,
    FbWskBoundConnection** result
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskReleaseBound(FbWskBoundConnection* connection);

#endif
