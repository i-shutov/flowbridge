#include <cstdlib>
#include <iostream>

#include "lifecycle.h"

static void need(bool value, const char* failure)
{
    if (!value) {
        std::cerr << failure << '\n';
        std::exit(1);
    }
}

// Exercise the shared decisions with controlled completion observations.
struct DrainFixture {
    FbWskGate gate{};
    FbWskOperation operation;
    bool has_socket;
    bool cancel_requested = false;
    unsigned cancellations = 0;
    unsigned closes = 0;

    DrainFixture(FbWskOperation initial_operation, bool accepted)
        : operation(initial_operation), has_socket(accepted)
    {
        need(FbWskGateEnter(&gate), "fixture admission");
    }

    FbWskDrainStep advance(bool complete, bool succeeded = false)
    {
        need(gate.outstanding == 1, "drain advanced a consumed handle");
        const auto step = FbWskNextDrainStep(operation, complete, cancel_requested,
                                             has_socket, succeeded);
        switch (step) {
        case FbWskRequestCancel:
            cancel_requested = true;
            ++cancellations;
            break;
        case FbWskCollectAccept:
            has_socket = succeeded;
            operation = FbWskIdle;
            break;
        case FbWskDiscardQuery:
            operation = FbWskIdle;
            break;
        case FbWskStartClose:
            has_socket = false;
            operation = FbWskClose;
            ++closes;
            break;
        case FbWskFree:
            FbWskGateLeave(&gate);
            break;
        case FbWskWaitForCompletion:
        case FbWskHoldCloseFailure:
            break;
        }
        return step;
    }
};

static void late_success_after_cancel()
{
    DrainFixture f(FbWskAccept, false);
    need(FbWskGateStop(&f.gate) == 1, "timed-out accept lost its rundown count");
    need(!FbWskGateEnter(&f.gate), "stop admitted a new accept");
    need(f.advance(false) == FbWskRequestCancel, "pending accept skipped cancellation");
    need(f.advance(false) == FbWskWaitForCompletion, "pending accept freed or canceled twice");
    need(f.advance(true, true) == FbWskCollectAccept, "late successful accept lost its socket");
    need(f.advance(false) == FbWskStartClose, "late accepted socket escaped close");
    need(f.advance(false) == FbWskWaitForCompletion, "close in flight was canceled or reclaimed");
    need(FbWskGateStop(&f.gate) == 1, "pending close opened the drain gate");
    need(f.advance(true, true) == FbWskFree, "completed successful close kept the handle");
    need(FbWskGateStop(&f.gate) == 0, "closed handle kept the drain gate busy");
    need(f.cancellations == 1 && f.closes == 1, "late accept was canceled or closed twice");
}

int main()
{
    late_success_after_cancel();
    {
        DrainFixture f(FbWskAccept, false);
        need(f.advance(true, true) == FbWskCollectAccept, "completed late accept was canceled");
        need(f.advance(false) == FbWskStartClose, "completed late accept was not closed");
        need(f.advance(true, true) == FbWskFree, "inline close completion was not consumed");
        need(f.cancellations == 0 && f.closes == 1, "inline completion issued extra provider calls");
    }
    {
        DrainFixture f(FbWskAccept, false);
        need(f.advance(false) == FbWskRequestCancel, "pending accept must request cancellation");
        need(f.advance(true) == FbWskCollectAccept, "canceled accept completion was not consumed");
        need(f.advance(false) == FbWskFree && f.closes == 0, "failed accept had no socket to close");
    }
    {
        DrainFixture f(FbWskQuerySocket, true);
        need(f.advance(false) == FbWskRequestCancel, "pending query skipped cancellation");
        need(f.advance(false) == FbWskWaitForCompletion, "pending query let close reuse its IRP");
        need(f.advance(true, true) == FbWskDiscardQuery, "late query result could escape cleanup");
        need(f.advance(false) == FbWskStartClose, "query timeout lost the accepted socket");
        need(f.advance(true, true) == FbWskFree, "query cleanup did not free after close");
    }
    {
        DrainFixture f(FbWskIdle, false);
        need(f.advance(false) == FbWskFree, "rejection before submission kept an idle handle");
        need(f.cancellations == 0 && f.closes == 0, "idle rejection dispatched provider work");
    }
    {
        DrainFixture f(FbWskIdle, true);
        need(FbWskGateStop(&f.gate) == 1, "bound handle did not block drain");
        need(f.advance(false) == FbWskStartClose, "released binding skipped close");
        need(f.advance(false) == FbWskWaitForCompletion, "release freed a pending close");
        need(f.advance(true, true) == FbWskFree, "successful release failed to drain");
        need(f.cancellations == 0 && f.closes == 1, "release issued extra provider calls");
    }
    {
        DrainFixture f(FbWskIdle, true);
        need(f.advance(false) == FbWskStartClose, "close-failure fixture did not submit close");
        need(f.advance(true) == FbWskHoldCloseFailure, "failed close released the handle");
        need(f.advance(true) == FbWskHoldCloseFailure, "failed close retried or released on polling");
        need(FbWskGateStop(&f.gate) == 1 && f.closes == 1, "failed close cleared the gate or retried");
    }
    {
        FbWskGate gate{};
        need(FbWskGateEnter(&gate) && FbWskGateEnter(&gate), "multiple handles not counted");
        need(FbWskGateStop(&gate) == 2, "stop lost an outstanding handle");
        FbWskGateLeave(&gate);
        need(FbWskGateStop(&gate) == 1, "first drain opened a gate with remaining work");
        FbWskGateLeave(&gate);
        need(FbWskGateStop(&gate) == 0 && !FbWskGateEnter(&gate), "stop reopened a drained gate");
    }
    {
        FbWskGate gate{ULONG_MAX, 0};
        need(!FbWskGateEnter(&gate) && gate.outstanding == ULONG_MAX, "outstanding count wrapped");
    }

    std::cout << "WSK_BINDING_LIFECYCLE_CASES_PASS=9\n";
}
