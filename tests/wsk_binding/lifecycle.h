#ifndef FLOWBRIDGE_WSK_BINDING_LIFECYCLE_H
#define FLOWBRIDGE_WSK_BINDING_LIFECYCLE_H

#include <limits.h>

typedef struct FbWskGate {
    unsigned long outstanding;
    int stopping;
} FbWskGate;

/* The WDK caller serializes all gate transitions under its lifetime lock. */
static int FbWskGateEnter(FbWskGate* gate)
{
    if (gate->stopping || gate->outstanding == ULONG_MAX)
        return 0;
    ++gate->outstanding;
    return 1;
}

static void FbWskGateLeave(FbWskGate* gate)
{
    --gate->outstanding;
}

static unsigned long FbWskGateStop(FbWskGate* gate)
{
    gate->stopping = 1;
    return gate->outstanding;
}

/* Admission and terminal authority share one lock with this transition. */
static unsigned long FbWskDisarmOwner(FbWskGate* gate, int* armed)
{
    *armed = 0;
    return FbWskGateStop(gate);
}

static int FbWskEnterArmedBinding(FbWskGate* gate, int armed)
{
    return armed && FbWskGateEnter(gate);
}

typedef enum FbWskOwnerProgress {
    FbWskOwnerWaitingForUsers,
    FbWskOwnerUsersJoined,
    FbWskOwnerListenerClosing,
    FbWskOwnerListenerClosed,
    FbWskOwnerListenerCloseFailed,
    FbWskOwnerProviderReleased,
    FbWskOwnerProviderDeregistered,
    FbWskOwnerCallbacksReturned
} FbWskOwnerProgress;

typedef enum FbWskOwnerStep {
    FbWskOwnerNeedsStop,
    FbWskOwnerNeedsBindingDrain,
    FbWskOwnerJoinUsers,
    FbWskOwnerCloseListener,
    FbWskOwnerCollectListenerClose,
    FbWskOwnerHoldListenerCloseFailure,
    FbWskOwnerReleaseProvider,
    FbWskOwnerDeregister,
    FbWskOwnerWaitForCallbacks,
    FbWskOwnerFree,
    FbWskOwnerInvalidState
} FbWskOwnerStep;

static FbWskOwnerStep FbWskNextOwnerStep(const FbWskGate* gate,
                                        FbWskOwnerProgress progress, int has_listener)
{
    if (!gate->stopping)
        return FbWskOwnerNeedsStop;
    if (gate->outstanding)
        return FbWskOwnerNeedsBindingDrain;

    switch (progress) {
    case FbWskOwnerWaitingForUsers:
        return FbWskOwnerJoinUsers;
    case FbWskOwnerUsersJoined:
        return has_listener ? FbWskOwnerCloseListener : FbWskOwnerReleaseProvider;
    case FbWskOwnerListenerClosing:
        return FbWskOwnerCollectListenerClose;
    case FbWskOwnerListenerClosed:
        return FbWskOwnerReleaseProvider;
    case FbWskOwnerListenerCloseFailed:
        return FbWskOwnerHoldListenerCloseFailure;
    case FbWskOwnerProviderReleased:
        return FbWskOwnerDeregister;
    case FbWskOwnerProviderDeregistered:
        return FbWskOwnerWaitForCallbacks;
    case FbWskOwnerCallbacksReturned:
        return FbWskOwnerFree;
    }
    return FbWskOwnerInvalidState;
}

typedef enum FbWskOperation {
    FbWskIdle,
    FbWskAccept,
    FbWskQuerySocket,
    FbWskClose
} FbWskOperation;

typedef enum FbWskDrainStep {
    FbWskWaitForCompletion,
    FbWskRequestCancel,
    FbWskCollectAccept,
    FbWskDiscardQuery,
    FbWskStartClose,
    FbWskHoldCloseFailure,
    FbWskFree
} FbWskDrainStep;

/* Completion is sampled only after the provider dispatch call returned. A
 * serialized owner keeps the IRP valid even if cancel races the callback. */
static FbWskDrainStep FbWskNextDrainStep(
    FbWskOperation operation, int complete, int cancel_requested, int has_socket,
    int close_succeeded)
{
    if (operation == FbWskIdle)
        return has_socket ? FbWskStartClose : FbWskFree;
    if (!complete)
        return operation == FbWskClose || cancel_requested
            ? FbWskWaitForCompletion : FbWskRequestCancel;
    if (operation == FbWskAccept)
        return FbWskCollectAccept;
    if (operation == FbWskQuerySocket)
        return FbWskDiscardQuery;
    return close_succeeded ? FbWskFree : FbWskHoldCloseFailure;
}

#endif
