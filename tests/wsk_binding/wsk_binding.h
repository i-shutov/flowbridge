#ifndef FLOWBRIDGE_WSK_BINDING_H
#define FLOWBRIDGE_WSK_BINDING_H

#include <ntddk.h>
#include <wsk.h>
#include "lifecycle.h"

/* Kernel-only prototype. Supply one initialized lifetime per owned listener.
 * Keep listener, policy and provider rundown through every live handle.
 * Serialize all operations on each handle and publish it with synchronization
 * when ownership moves between threads. Lifetime and spin-locked authority
 * storage are nonpaged. All pointers are kernel-private. */
struct FbWskClaimPolicy;
struct FbWskListenerEpoch;
typedef struct FbWskBoundConnection FbWskBoundConnection;
typedef struct FbWskDrain FbWskDrain;

typedef struct FbWskBindingLifetime {
    KSPIN_LOCK lock;
    FbWskGate gate;
} FbWskBindingLifetime;

_IRQL_requires_(PASSIVE_LEVEL)
void FbWskInitializeBindingLifetime(FbWskBindingLifetime* lifetime);

/* Closes admission. Success means all admitted binding handles drained.
 * Admitted work can still commit until the caller disarms policy under its
 * authority lock. The caller owns listener close, joined caller/worker and
 * callback rundown, provider release and WSK deregistration. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskStopBinding(FbWskBindingLifetime* lifetime, PULONG outstanding);

/* Uses one three-second budget for accept/query completion waits. WSK
 * dispatch call latency is outside the prototype's control. A failure after
 * allocation hands back a cleanup-only handle. Keep it until drain succeeds. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskAcceptBound(
    FbWskBindingLifetime* lifetime, PWSK_SOCKET listener,
    const struct FbWskListenerEpoch* listener_epoch,
    PKSPIN_LOCK policy_lock,
    struct FbWskClaimPolicy* policy_state,
    FbWskBoundConnection** result, FbWskDrain** drain
    );

/* Moves a successful binding to the same cleanup path without calling WSK. */
_IRQL_requires_(PASSIVE_LEVEL)
FbWskDrain* FbWskReleaseBound(FbWskBoundConnection** connection);

/* Advances cleanup once on the serialized owner, without a completion wait.
 * Cancel and close calls can execute provider code. STATUS_PENDING keeps the
 * handle live. A failed close quarantines the handle and keeps the gate busy.
 * Only STATUS_SUCCESS consumes and clears the handle. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskDrainBound(FbWskDrain** handle);

#endif
