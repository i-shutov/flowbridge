#ifndef FLOWBRIDGE_WSK_BINDING_H
#define FLOWBRIDGE_WSK_BINDING_H

#include <ntddk.h>
#include <wsk.h>

/* Kernel-only. The containing driver keeps its nonpaged authority lock and
 * process epoch table alive until the owner is destroyed. It publishes one
 * owner per fresh generation and serializes startup, arm, stop and teardown.
 * It must also serialize and synchronize every binding handle handoff. */
struct FbWskClaimPolicy;
struct FbWskListenerEpoch;
struct FbEpochTable;
typedef struct FbWskOwner FbWskOwner;
typedef struct FbWskBoundConnection FbWskBoundConnection;
typedef struct FbWskDrain FbWskDrain;

/* Invoked by the serialized owner at PASSIVE_LEVEL. Success attests that
 * the named condition is complete. Other statuses leave the owner live. */
typedef NTSTATUS FbWskOwnerBarrier(PVOID context);

/* listener_process is a trusted, referenced process object selected by the
 * containing driver. The owner takes its own reference and receipt history. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskCreateOwner(
    PEPROCESS listener_process, ULONG64 generation, ADDRESS_FAMILY family,
    USHORT port_be, PKSPIN_LOCK authority_lock, struct FbEpochTable* epochs,
    FbWskOwnerBarrier* join_users, FbWskOwnerBarrier* wait_callbacks,
    PVOID barrier_context, FbWskOwner** result
    );

/* This one-shot startup may wait for WSK socket creation and bind. The owner
 * must go through stop and rundown even if startup fails midway. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskStartOwner(FbWskOwner* owner);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskArmOwner(FbWskOwner* owner);

/* The callout reads the exact redirect target and operates on the generation
 * ledger under this lock. The entry point needs a live owner publication.
 * Success keeps the lock held until FbWskUnlockOwnerAuthority. */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS FbWskLockOwnerAuthority(
    FbWskOwner* owner, PKIRQL previous_irql, const struct FbWskClaimPolicy** policy,
    const struct FbWskListenerEpoch** target
    );

_IRQL_requires_(DISPATCH_LEVEL)
void FbWskUnlockOwnerAuthority(FbWskOwner* owner, KIRQL previous_irql);

/* Disarms terminal authority and closes admission together. STATUS_SUCCESS
 * here covers the number of binding handles. Owner rundown is separate. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskStopOwner(FbWskOwner* owner, PULONG outstanding);

/* After stop and binding drain, join_users must withdraw owner publication
 * and join all callout and worker entries. Close then completes before
 * provider release and deregistration. wait_callbacks must establish that
 * completion routines returned before the owner can be destroyed. The
 * callbacks must be retryable and must never reenter owner rundown. Only
 * STATUS_SUCCESS consumes the owner. A failed listener close quarantines it. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskAdvanceOwnerRundown(FbWskOwner** owner);

/* Uses one three-second budget for accept/query completion waits. WSK
 * dispatch call latency is outside the prototype's control. A failure after
 * allocation hands back a cleanup-only handle. Keep it until drain succeeds. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS FbWskAcceptBound(
    FbWskOwner* owner, FbWskBoundConnection** result, FbWskDrain** drain
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
