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
