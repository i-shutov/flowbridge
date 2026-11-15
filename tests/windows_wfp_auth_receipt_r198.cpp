// Compile and execute exactly the C source used by the native WFP driver,
// without loading any kernel component. These are logic and ABI tests ONLY.
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include "../native/windows/wfp/auth_receipt.h"

static void need(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
static FbAuthOrigin origin(std::uint64_t pid=704, unsigned seq=1) {
    FbAuthOrigin o{};
    o.pid=pid;
    o.creation_100ns=1000000 + seq;
    o.process_start_key=2000000 + seq;
    o.endpoint=3000000 + seq;
    o.flow_id=4000000 + seq;
    o.broker_pid=1234;
    o.family=4;
    o.port_be=0xBB01; // raw little-endian bytes 01 bb = TCP/443 network order
    o.original_ip[0]=192;o.original_ip[1]=0;o.original_ip[2]=2;o.original_ip[3]=17;
    return o;
}
static FbAuthOrigin observed(const FbAuthOrigin& issued) {
    auto copy=issued;copy.flow_id=0;return copy;
}
static int consume(FbAuthBook& book, const FbAuthOrigin& issued) {
    const auto matched = observed(issued);
    return FbAuthConsumeObserved(&book, &matched);
}
static void exact_kernel_receipt_single_use() {
    FbAuthBook book{};
    const auto a=origin();
    need(FbAuthIssue(&book,&a),"WFP-issued origin rejected");
    const auto q=observed(a);
    need(FbAuthConsumeObserved(&book,&q),"matching selected original was denied");
    need(!FbAuthConsumeObserved(&book,&q),"replayed WFP AUTH was allowed");
    need(book.slots[0].state==2,"WFP receipt not consumed exactly once");
}
static void sibling_direct_or_physical_ssh_is_not_original() {
    for(int index=0;index<5;++index) {
        FbAuthBook book{};const auto a=origin();need(FbAuthIssue(&book,&a),"setup");
        auto q=observed(a);
        switch(index) {
            case 0: q.original_ip[0]=203;break; // physical SSH different server
            case 1: q.port_be=0x1600;break;      // selected sibling direct port
            case 2: q.endpoint+=5;break;        // unrelated TCP flow
            case 3: q.broker_pid+=1;break;      // spoofed redirect target
            default: q.family=6;break;          // v4 ticket on v6 socket
        }
        need(!FbAuthConsumeObserved(&book,&q),"a different TCP/socket route got AUTH");
        need(consume(book,a),
             "unrelated fake AUTH consumed legitimate original");
    }
}
static void live_process_incarnation_required() {
    for(int index=0;index<3;++index) {
        FbAuthBook book{};const auto a=origin();need(FbAuthIssue(&book,&a),"setup");
        auto q=observed(a);
        if(index==0)q.pid++;
        else if(index==1)q.creation_100ns++;
        else q.process_start_key++;
        need(!FbAuthConsumeObserved(&book,&q),"PID/epoch/start-key mismatch was admitted");
        need(consume(book,a),"failed owner probe consumed ticket");
    }
}
static void missing_metadata_or_unissued_flow_is_denied() {
    FbAuthBook empty{};const auto a=origin();
    need(!consume(empty,a),"no OS redirect issued yet");
    for(int index=0;index<5;++index) {
        FbAuthBook book{};need(FbAuthIssue(&book,&a),"setup");
        auto q=observed(a);
        if(index==0)q.pid=0;
        else if(index==1)q.creation_100ns=0;
        else if(index==2)q.process_start_key=0;
        else if(index==3)q.endpoint=0;
        else q.broker_pid=0;
        need(!FbAuthConsumeObserved(&book,&q),"missing auth metadata accepted");
    }
}
static void process_exit_and_pid_reuse_retire() {
    FbAuthBook book{};const auto a=origin();need(FbAuthIssue(&book,&a),"setup");
    need(FbAuthProcessExit(&book,a.pid,a.creation_100ns,a.process_start_key),
         "process exit did not revoke");
    need(!consume(book,a),"dead PID authorized selected TCP");
    auto b=origin(a.pid,2);
    need(FbAuthIssue(&book,&b),"reused PID new epoch rejected");
    need(consume(book,b),"fresh PID epoch rejected");
    need(!consume(book,a),"old process ghost remained authorized");
}
static void stale_exit_poison_is_fail_closed() {
    FbAuthBook book{};auto a=origin();need(FbAuthIssue(&book,&a),"setup");
    auto wrong=a;wrong.creation_100ns++;
    need(!FbAuthProcessExit(&book,wrong.pid,wrong.creation_100ns,wrong.process_start_key)
         && book.lost,"wrong epoch process exit did not poison");
    need(!consume(book,a),
         "poisoned kernel auth book still admits packets");
}
static void no_endpoint_reissue_and_duplicate_flow_id() {
    for(int which=0;which<2;++which) {
        FbAuthBook book{};auto a=origin();need(FbAuthIssue(&book,&a),"setup");
        need(FbAuthRetire(&book,&a),"ticket retirement unavailable");
        auto b=origin(708,2);
        if(which==0)b.endpoint=a.endpoint;
        else b.flow_id=a.flow_id;
        need(!FbAuthIssue(&book,&b) && book.lost,"endpoint/sequence reused after retirement");
        need(!consume(book,a),"lost table continued permitting");
    }
}
static void bounded_capacity_latches_fail_closed() {
    FbAuthBook book{};
    for(unsigned i=0;i<FB_AUTH_CAP;++i) {
        auto a=origin(1024+4*i,i+1);
        need(FbAuthIssue(&book,&a),"unexpected auth book saturation");
        need(consume(book,a),"initial AUTH consumed failure");
    }
    auto overflow=origin(999999,FB_AUTH_CAP+1);
    need(!FbAuthIssue(&book,&overflow) && book.lost,
         "auth book silently evicted a previously authorized flow");
    auto old=origin(1024,1);
    need(!consume(book,old),
         "full/lost kernel ticket book allowed replay");
}
static void even_untrusted_unknown_process_cannot_mint_ticket() {
    for(int which=0;which<5;++which) {
        FbAuthBook book{};auto a=origin();
        if(which==0)a.pid=0;
        else if(which==1)a.creation_100ns=0;
        else if(which==2)a.process_start_key=0;
        else if(which==3)a.endpoint=0;
        else for(auto &byte : a.original_ip) byte=0;
        need(!FbAuthIssue(&book,&a) && book.lost,
             "untrusted origin minted an authorization ticket");
    }
}

static void claim_requires_completed_os_auth_and_is_terminal() {
    FbAuthBook book{};
    const auto source=origin();
    need(FbAuthIssue(&book,&source),"issue failed");
    need(!FbAuthClaim(&book,&source),"claim preceded real OS AUTH");
    need(consume(book,source),"genuine initial OS AUTH not consumed");
    need(FbAuthClaim(&book,&source),"terminal claim of OS AUTH failed");
    need(book.slots[0].state==3,"terminal claim did not retire record");
    need(!FbAuthClaim(&book,&source),"replayed claim accepted");
    need(!consume(book,source),"initial AUTH replayed after terminal claim");
}
static void claim_rejects_all_foreign_origin_fields_without_consuming_good() {
    for (int which=0;which<9;++which) {
        FbAuthBook book{};
        const auto source=origin();
        need(FbAuthIssue(&book,&source) && consume(book,source),"setup");
        auto altered=source;
        switch (which) {
            case 0: altered.pid++;break;
            case 1: altered.creation_100ns++;break;
            case 2: altered.process_start_key++;break;
            case 3: altered.endpoint++;break;
            case 4: altered.flow_id++;break;
            case 5: altered.broker_pid++;break;
            case 6: altered.original_ip[2]++;break;
            case 7: altered.port_be++;break;
            default: altered.family=6;break;
        }
        need(!FbAuthClaim(&book,&altered),"foreign process/sibling/SSH claim accepted");
        need(FbAuthClaim(&book,&source),"bad claim consumed legitimate OS ticket");
    }
}
static void claim_denied_after_original_process_death_or_driver_loss() {
    for (int which=0;which<2;++which) {
        FbAuthBook book{};
        const auto source=origin();
        need(FbAuthIssue(&book,&source) && consume(book,source),"setup");
        if(which==0)
            need(FbAuthProcessExit(&book,source.pid,source.creation_100ns,
                                   source.process_start_key),"exit");
        else
            book.lost=1; // terminal driver disarm under owner stop
        need(!FbAuthClaim(&book,&source),"dead/disarmed flow admitted after AUTH");
    }
}
static void empty_or_invalid_claim_cannot_mint_kernel_authorization() {
    FbAuthBook book{};
    const auto source=origin();
    need(!FbAuthClaim(&book,&source),"unissued claim accepted");
    need(FbAuthIssue(&book,&source) && consume(book,source),"setup");
    auto bad=source;
    bad.flow_id=0;
    need(!FbAuthClaim(&book,&bad),"zero flow sequence accepted");
    need(!FbAuthClaim(nullptr,&source),"null kernel book accepted");
    need(!FbAuthClaim(&book,nullptr),"null process origin accepted");
    need(FbAuthClaim(&book,&source),"invalid requests destroyed real receipt");
}

int main() {
    try {
        exact_kernel_receipt_single_use();
        sibling_direct_or_physical_ssh_is_not_original();
        live_process_incarnation_required();
        missing_metadata_or_unissued_flow_is_denied();
        process_exit_and_pid_reuse_retire();
        stale_exit_poison_is_fail_closed();
        no_endpoint_reissue_and_duplicate_flow_id();
        bounded_capacity_latches_fail_closed();
        even_untrusted_unknown_process_cannot_mint_ticket();
        claim_requires_completed_os_auth_and_is_terminal();
        claim_rejects_all_foreign_origin_fields_without_consuming_good();
        claim_denied_after_original_process_death_or_driver_loss();
        empty_or_invalid_claim_cannot_mint_kernel_authorization();
        std::cout
          << "{\"schema\":\"flowbridge-wfp-r198-auth-receipt-source-v1\","
          << "\"status\":\"C_SOURCE_LOGIC_PASS_NATIVE_WFP_NOT_RUN\","
          << "\"cases_pass\":13,\"kernel_callbacks_executed\":false,"
          << "\"physical_proxy_ssh_verified\":false,\"native_g2_accepted\":false,"
          << "\"release_accepted\":false}" << std::endl;
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"FAIL "<<e.what()<<std::endl;return 1;
    }
}
