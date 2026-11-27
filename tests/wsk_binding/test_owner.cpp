#include <cstdlib>
#include <iostream>

#include "claim.h"
#include "lifecycle.h"

static void need(bool value, const char* failure)
{
    if (!value) {
        std::cerr << failure << '\n';
        std::exit(1);
    }
}

static void stop_blocks_admitted_terminal_claim()
{
    FbEpochTable epochs{};
    FbAuthBook history{};
    FbWskGate gate{};
    FbWskClaimPolicy policy{&epochs, &history, 7, 104, 1};
    const FbWskListenerEpoch target{7, 104, FB_WSK_AF_INET, 0x3412};
    const FbAuthOrigin origin{128, 201, 302, 504, 605, 104, 0xBB01, 4, {192, 0, 2, 10}};
    FbAuthOrigin observed = origin;
    FbRedirectContext context{};

    context.magic = FB_REDIRECT_MAGIC;
    context.version = FB_REDIRECT_VERSION;
    context.size = FB_REDIRECT_CONTEXT_BYTES;
    context.original_process_id = origin.pid;
    context.original_process_creation_100ns = origin.creation_100ns;
    context.original_process_start_key = origin.process_start_key;
    context.original_transport_endpoint = origin.endpoint;
    context.flow_id = origin.flow_id;
    context.address_family = target.address_family;
    context.destination_port_be = origin.port_be;
    for (unsigned i = 0; i < sizeof(origin.original_ip); ++i)
        context.destination_address[i] = origin.original_ip[i];
    context.process_path_chars = 1;
    context.process_path[0] = 'X';
    observed.flow_id = 0;

    need(FbEpochInsert(&epochs, {origin.pid, origin.creation_100ns, origin.process_start_key, 403}),
         "fixture origin epoch");
    need(FbAuthIssue(&history, &origin) && FbAuthConsumeObserved(&history, &observed),
         "fixture authorized receipt");
    auto before_stop = history;
    FbWskClaimPolicy baseline{&epochs, &before_stop, 7, 104, 1};
    need(FbWskCommitAcceptedContext(&baseline, &target, &context), "baseline claim failed");

    need(FbWskEnterArmedBinding(&gate, policy.armed), "armed owner could not admit");
    need(FbWskDisarmOwner(&gate, &policy.armed) == 1, "stop lost the active binding");
    need(!FbWskCommitAcceptedContext(&policy, &target, &context), "admitted work claimed after stop");
    need(history.slots[0].state == 2, "stopped authority consumed the receipt");
    need(!FbWskEnterArmedBinding(&gate, 1), "stopped gate accepted stale armed state");
    FbWskGateLeave(&gate);
    need(FbWskDisarmOwner(&gate, &policy.armed) == 0, "stopped owner failed to drain");
}

static void broker_epoch_checks_object_and_pid_incarnation()
{
    FbEpochTable epochs{};
    const FbEpochRecord broker{104, 210, 320, 430};
    need(!FbWskBrokerEpochIsLive(&epochs, &broker), "unknown process treated as a live broker");
    need(FbEpochInsert(&epochs, broker), "fixture broker epoch");
    need(FbWskBrokerEpochIsLive(&epochs, &broker), "exact broker denied");
    FbEpochRecord other = broker;
    ++other.process_token;
    need(!FbWskBrokerEpochIsLive(&epochs, &other), "different process object accepted");
    other = broker;
    ++other.creation_100ns;
    need(!FbWskBrokerEpochIsLive(&epochs, &other), "different creation time accepted");
    other = broker;
    ++other.start_key;
    need(!FbWskBrokerEpochIsLive(&epochs, &other), "different start key accepted");
    need(FbEpochExit(&epochs, broker), "fixture broker exit");
    need(FbEpochInsert(&epochs, other), "fixture broker PID reuse");
    need(!FbWskBrokerEpochIsLive(&epochs, &broker), "same PID substituted for exited broker");
}

int main()
{
    stop_blocks_admitted_terminal_claim();
    broker_epoch_checks_object_and_pid_incarnation();
    {
        FbWskGate gate{};
        need(!FbWskEnterArmedBinding(&gate, 0) && gate.outstanding == 0,
             "startup or disarmed owner admitted a binding");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerWaitingForUsers, 1) == FbWskOwnerNeedsStop,
             "running owner started rundown");
    }
    {
        FbWskGate gate{1, 1};
        need(FbWskNextOwnerStep(&gate, FbWskOwnerWaitingForUsers, 1) == FbWskOwnerNeedsBindingDrain,
             "live or quarantined handle allowed user join and listener close");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerListenerClosed, 0) == FbWskOwnerNeedsBindingDrain,
             "live or quarantined handle allowed provider release");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerCallbacksReturned, 0) == FbWskOwnerNeedsBindingDrain,
             "live or quarantined handle allowed owner free");
    }
    {
        FbWskGate gate{0, 1};
        need(FbWskNextOwnerStep(&gate, FbWskOwnerWaitingForUsers, 1) == FbWskOwnerJoinUsers,
             "zero bindings skipped the required caller and worker join");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerUsersJoined, 1) == FbWskOwnerCloseListener,
             "live listener skipped its close after the join");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerUsersJoined, 0) == FbWskOwnerReleaseProvider,
             "startup without a listener incorrectly requested close");
    }
    {
        FbWskGate gate{0, 1};
        need(FbWskNextOwnerStep(&gate, FbWskOwnerListenerClosing, 0) == FbWskOwnerCollectListenerClose,
             "pending close released the provider or allowed another close");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerListenerCloseFailed, 0) == FbWskOwnerHoldListenerCloseFailure,
             "failed close released the provider or allowed another close");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerListenerClosed, 0) == FbWskOwnerReleaseProvider,
             "successful close did not allow provider release");
    }
    {
        FbWskGate gate{0, 1};
        need(FbWskNextOwnerStep(&gate, FbWskOwnerProviderReleased, 0) == FbWskOwnerDeregister,
             "rundown skipped deregistration after provider release");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerProviderDeregistered, 0) == FbWskOwnerWaitForCallbacks,
             "deregistration or a completion event alone permitted free");
        need(FbWskNextOwnerStep(&gate, FbWskOwnerCallbacksReturned, 0) == FbWskOwnerFree,
             "completed callback rundown kept the owner");
    }

    std::cout << "WSK_BINDING_OWNER_CASES_PASS=7\n";
}
