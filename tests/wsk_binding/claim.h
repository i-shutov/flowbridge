#ifndef FLOWBRIDGE_WSK_BINDING_CLAIM_H
#define FLOWBRIDGE_WSK_BINDING_CLAIM_H

#include "../../native/windows/wfp/auth_receipt.h"
#include "../../native/windows/wfp/process_epoch.h"
#include "../../native/windows/wfp/redirect_context.h"

/* The WDK translation unit checks these constants against the SDK. */
#define FB_WSK_AF_INET 2u
#define FB_WSK_AF_INET6 23u

typedef struct FbWskClaimPolicy {
    FbEpochTable* epochs;
    FbAuthBook* auth;
    FbUint64 generation;
    FbUint32 broker_pid;
    int armed;
} FbWskClaimPolicy;

typedef struct FbWskListenerEpoch {
    FbUint64 generation;
    FbUint32 broker_pid;
    FbUint16 address_family;
    FbUint16 port_be;
} FbWskListenerEpoch;

static int FbWskBrokerEpochIsLive(const FbEpochTable* epochs, const FbEpochRecord* broker)
{
    FbEpochRecord live = {0};
    return FbEpochLookup(epochs, broker->pid, &live) &&
           live.creation_100ns == broker->creation_100ns &&
           live.start_key == broker->start_key &&
           live.process_token == broker->process_token;
}

/* Called under the authority spin lock after both queries succeeded on the
 * accepted WSK object. The caller must keep policy/ledger storage alive and
 * never carry receipts across a policy-generation transition. */
static int FbWskCommitAcceptedContext(FbWskClaimPolicy* policy,
                                      const FbWskListenerEpoch* listener,
                                      const FbRedirectContext* context) {
    FbAuthOrigin exact = {0};
    FbEpochRecord live = {0};
    unsigned i;

    if (!policy || !policy->armed || !listener || !context ||
        !listener->generation || policy->generation != listener->generation ||
        !listener->broker_pid || policy->broker_pid != listener->broker_pid ||
        !listener->port_be || context->address_family != listener->address_family ||
        context->magic != FB_REDIRECT_MAGIC ||
        context->version != FB_REDIRECT_VERSION ||
        context->size != FB_REDIRECT_CONTEXT_BYTES ||
        context->original_process_id == listener->broker_pid ||
        context->ipv6_scope_id != 0 || !context->process_path_chars ||
        context->process_path_chars >= FB_PROCESS_PATH_CHARS)
        return 0;

    for (i = 0; i < sizeof(context->reserved); ++i)
        if (context->reserved[i] != 0) return 0;
    for (i = 0; i < FB_PROCESS_PATH_CHARS; ++i) {
        if (i < context->process_path_chars) {
            if (context->process_path[i] < 32) return 0;
        } else if (context->process_path[i] != 0) return 0;
    }

    exact.pid = context->original_process_id;
    exact.creation_100ns = context->original_process_creation_100ns;
    exact.process_start_key = context->original_process_start_key;
    exact.endpoint = context->original_transport_endpoint;
    exact.flow_id = context->flow_id;
    exact.broker_pid = listener->broker_pid;
    exact.port_be = context->destination_port_be;
    exact.family = context->address_family == FB_WSK_AF_INET ? 4 :
                   context->address_family == FB_WSK_AF_INET6 ? 6 : 0;
    for (i = 0; i < sizeof(exact.original_ip); ++i)
        exact.original_ip[i] = context->destination_address[i];

    return FbEpochLookup(policy->epochs, exact.pid, &live) &&
           live.creation_100ns == exact.creation_100ns &&
           live.start_key == exact.process_start_key &&
           FbAuthClaim(policy->auth, &exact);
}

#endif
