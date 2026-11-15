// Real compiled C-compatible WFP process-incarnation ledger regression.
// No system filter, driver loading, service change, or network I/O.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include "../native/windows/wfp/process_epoch.h"
#include "../native/windows/wfp/redirect_context.h"
static void need(bool yes, const char* what) {
    if (!yes) throw std::runtime_error(what);
}
static FbEpochRecord rec(std::uint64_t pid, std::uint64_t generation) {
    return {pid, 1000 + generation, 2000 + generation, 3000 + generation};
}
static void valid_process_creation_exit() {
    FbEpochTable t{};
    auto a=rec(1004,1);
    need(FbEpochLookup(&t,a.pid,&a)==0,"unobserved process was admitted");
    a=rec(1004,1);
    need(FbEpochInsert(&t,a)==1,"real creation witness rejected");
    FbEpochRecord observed{};
    need(FbEpochLookup(&t,a.pid,&observed) && observed.creation_100ns==a.creation_100ns &&
         observed.start_key==a.start_key && observed.process_token==a.process_token,
         "birth/start-key/process-token changed");
    need(FbEpochExit(&t,a)==1,"real process exit not removed");
    need(!FbEpochLookup(&t,a.pid,&observed),"terminated PID still admitted");
    auto newer=rec(a.pid,2);
    need(FbEpochInsert(&t,newer)==1 &&
         FbEpochLookup(&t,newer.pid,&observed) &&
         observed.creation_100ns==newer.creation_100ns &&
         observed.start_key==newer.start_key, "same PID new OS epoch was confused");
}
static void duplicate_process_pid_poison() {
    FbEpochTable t{};
    const auto a=rec(1004,1);
    need(FbEpochInsert(&t,a)==1,"first incarnation failed");
    need(!FbEpochInsert(&t,rec(1004,2)) && t.lost,"duplicate live PID did not poison");
    FbEpochRecord out{};
    need(!FbEpochLookup(&t,1004,&out),"poisoned process ledger still admitted");
}
static void out_of_order_exit_poison() {
    FbEpochTable t{};
    const auto a=rec(1004,1);
    need(FbEpochInsert(&t,a)==1,"first incarnation failed");
    need(!FbEpochExit(&t,rec(1004,2)) && t.lost,
         "stale/different process token could delete the original record");
    FbEpochRecord out{};
    need(!FbEpochLookup(&t,1004,&out),"incorrect exit failed to revoke admission");
}
static void empty_zero_epoch_and_key_poison() {
    for(int which=0;which<4;++which) {
        FbEpochTable t{};auto x=rec(42,1);
        if(which==0)x.pid=0;
        if(which==1)x.creation_100ns=0;
        if(which==2)x.start_key=0;
        if(which==3)x.process_token=0;
        need(!FbEpochInsert(&t,x) && t.lost,"zero-source identity allowed");
        FbEpochRecord o{};
        need(!FbEpochLookup(&t,42,&o),"zero identity poisoned a foreign process");
    }
}
static void bucket_exhaustion_no_evict() {
    FbEpochTable t{};
    std::array<std::vector<std::uint64_t>,FB_EPOCH_BUCKETS> buckets{};
    for(std::uint64_t pid=4;pid<60000;pid+=4) {
        auto& group=buckets[FbEpochBucket(pid)];
        if(group.size()<=FB_EPOCH_WAYS)group.push_back(pid);
    }
    const auto found=std::find_if(buckets.begin(),buckets.end(),
                                 [](const auto& group){return group.size()>FB_EPOCH_WAYS;});
    need(found!=buckets.end(),"could not find table collision fixtures");
    for(unsigned i=0;i<FB_EPOCH_WAYS;++i)
        need(FbEpochInsert(&t,rec((*found)[i],i+1))==1,
             "8 real bucket entries could not be admitted");
    need(!FbEpochInsert(&t,rec((*found)[FB_EPOCH_WAYS],999)) && t.lost,
         "9th same-bucket process evicted another owner");
    FbEpochRecord observed{};
    need(!FbEpochLookup(&t,(*found)[0],&observed),"saturated ledger kept allowing");
}
static void no_fabricated_redirect_claim() {
    static_assert(FB_REDIRECT_VERSION==3,"WFP context v3 required");
    static_assert(FB_REDIRECT_CONTEXT_BYTES==2136,"V3 wire byte size drift");
    static_assert(sizeof(FbRedirectContext)==2136,"V3 packed kernel/user structure drift");
    static_assert(offsetof(FbRedirectContext,original_process_creation_100ns)==2112,
                  "kernel birth epoch offset mismatch");
    static_assert(offsetof(FbRedirectContext,original_process_start_key)==2120,
                  "kernel start key offset mismatch");
    static_assert(offsetof(FbRedirectContext,original_transport_endpoint)==2128,
                  "WFP endpoint handle offset mismatch");
}
int main() {
    try {
        valid_process_creation_exit();
        duplicate_process_pid_poison();
        out_of_order_exit_poison();
        empty_zero_epoch_and_key_poison();
        bucket_exhaustion_no_evict();
        no_fabricated_redirect_claim();
        std::cout << "{\"schema\":\"flowbridge-wfp-epoch-v3-qa-v1\","
                  << "\"source\":\"real C production ledger\","
                  << "\"cases_pass\":6,\"process_birth_epoch_source\":\"callback_only\","
                  << "\"kernel_callback_executed\":false,\"wfp_driver_loaded\":false,"
                  << "\"auth_connect_covered\":false,\"accepted_redirect_context_proved\":false,"
                  << "\"g2_native_pass\":false,\"physical_no_direct_proved\":false,"
                  << "\"release_1_0_accepted\":false}" << std::endl;
    } catch(const std::exception& e) {
        std::cerr<<"FAIL: "<<e.what()<<std::endl;return 1;
    }
    return 0;
}
