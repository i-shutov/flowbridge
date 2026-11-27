#include <cstdlib>
#include <iostream>

#include "claim.h"

static_assert(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES, "redirect context ABI");

static void need(bool value, const char* failure)
{
    if (!value) {
        std::cerr << failure << '\n';
        std::exit(1);
    }
}

struct Fixture {
    FbEpochTable epochs{};
    FbAuthBook book{};
    FbWskClaimPolicy policy{&epochs, &book, 7, 104, 1};
    FbWskListenerEpoch listener{7, 104, FB_WSK_AF_INET, 0x3412};
    FbEpochRecord incarnation{128, 201, 302, 403};
    FbRedirectContext context{};
    FbAuthOrigin origin{128, 201, 302, 504, 605, 104, 0xBB01, 4, {192, 0, 2, 10}};

    explicit Fixture(bool authorize = true, bool ipv6 = false)
    {
        if (ipv6) {
            listener.address_family = FB_WSK_AF_INET6;
            origin.family = 6;
            origin.original_ip[0] = 0x20;
            origin.original_ip[1] = 0x01;
            origin.original_ip[2] = 0x0d;
            origin.original_ip[3] = 0xb8;
            origin.original_ip[15] = 1;
        }

        context.magic = FB_REDIRECT_MAGIC;
        context.version = FB_REDIRECT_VERSION;
        context.size = FB_REDIRECT_CONTEXT_BYTES;
        context.original_process_id = origin.pid;
        context.original_process_creation_100ns = origin.creation_100ns;
        context.original_process_start_key = origin.process_start_key;
        context.original_transport_endpoint = origin.endpoint;
        context.flow_id = origin.flow_id;
        context.address_family = listener.address_family;
        context.destination_port_be = origin.port_be;
        for (unsigned i = 0; i < sizeof(origin.original_ip); ++i)
            context.destination_address[i] = origin.original_ip[i];
        context.process_path_chars = 1;
        context.process_path[0] = 'X';

        need(FbEpochInsert(&epochs, incarnation), "fixture epoch insert");
        need(FbAuthIssue(&book, &origin), "fixture ticket issue");
        if (authorize)
            initial_auth();
    }

    void initial_auth()
    {
        auto observed = origin;
        observed.flow_id = 0;
        need(FbAuthConsumeObserved(&book, &observed), "fixture initial AUTH");
    }

    bool claim()
    {
        return FbWskCommitAcceptedContext(&policy, &listener, &context) != 0;
    }
};

int main()
{
    {
        Fixture f;
        need(f.claim(), "first valid kernel receipt denied");
        need(!f.claim(), "receipt replay allowed");
    }
    {
        Fixture f(false);
        need(!f.claim(), "receipt accepted before initial AUTH");
        f.initial_auth();
        need(f.claim(), "early attempt burned a valid ticket");
    }
    {
        Fixture f;
        need(FbEpochExit(&f.epochs, f.incarnation), "fixture epoch exit");
        ++f.incarnation.start_key;
        ++f.incarnation.creation_100ns;
        need(FbEpochInsert(&f.epochs, f.incarnation), "fixture PID reuse");
        need(!f.claim(), "stale PID incarnation accepted");
    }
    {
        Fixture f;
        ++f.policy.generation;
        need(!f.claim(), "stale listener policy allowed");
        need(f.book.slots[0].state == 2, "stale policy burned ticket");
    }
    {
        Fixture f;
        f.policy.armed = 0;
        need(!f.claim(), "disabled policy accepted");
        need(f.book.slots[0].state == 2, "disabled policy burned ticket");
    }
    {
        Fixture f;
        ++f.listener.broker_pid;
        need(!f.claim(), "wrong broker accepted");
        need(f.book.slots[0].state == 2, "wrong broker burned ticket");
    }
    {
        Fixture f;
        ++f.context.flow_id;
        need(!f.claim(), "different redirect context accepted");
        --f.context.flow_id;
        need(f.claim(), "different context burned a valid ticket");
    }
    {
        Fixture f;
        f.context.reserved[0] = 1;
        need(!f.claim(), "malformed context accepted");
        f.context.reserved[0] = 0;
        need(f.claim(), "malformed context burned a valid ticket");
    }

    {
        Fixture f(true, true);
        f.listener.address_family = FB_WSK_AF_INET;
        need(!f.claim(), "IPv6 context accepted on an IPv4 listener");
        f.listener.address_family = FB_WSK_AF_INET6;
        need(f.claim(), "valid IPv6 receipt denied");
    }

    std::cout << "WSK_BINDING_AUTHORITY_CASES_PASS=9\n";
}
