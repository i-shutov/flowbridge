#ifndef FLOWBRIDGE_WFP_AUTH_RECEIPT_H
#define FLOWBRIDGE_WFP_AUTH_RECEIPT_H
#include "wire_types.h"

/* Product source, deliberately bounded. Kernel spinlock protects every
 * mutation and lookup. A record can only be issued by OS ALE_CONNECT_REDIRECT
 * with a live kernel process-incarnation lookup. User mode cannot mint one.
 *
 * State 1=issued, 2=initial AUTH consumed, 3=retired. Entries/tombstones
 * are never reused during an armed driver session: endpoint reuse and
 * exhausted capacity fail closed. This prototype intentionally limits the
 * number of native selected redirects until a generation-safe reclamation
 * scheme is accepted. No release G2 credit.
 */
#define FB_AUTH_CAP 512u
typedef struct FbAuthOrigin {
    FbUint64 pid;
    FbUint64 creation_100ns;
    FbUint64 process_start_key;
    FbUint64 endpoint;
    FbUint64 flow_id;
    FbUint32 broker_pid;
    FbUint16 port_be;
    FbUint8 family;
    FbUint8 original_ip[16];
} FbAuthOrigin;
typedef struct FbAuthSlot {
    FbAuthOrigin origin;
    FbUint8 state;
} FbAuthSlot;
typedef struct FbAuthBook {
    FbAuthSlot slots[FB_AUTH_CAP];
    FbUint32 count;
    FbUint32 lost;
} FbAuthBook;

static int FbAuthOriginValid(const FbAuthOrigin* item) {
    unsigned i;
    int nonzero = 0;
    if (!item || !item->pid || !item->creation_100ns ||
        !item->process_start_key || !item->endpoint || !item->flow_id ||
        !item->broker_pid || !item->port_be ||
        (item->family != 4 && item->family != 6)) return 0;
    for (i = 0; i < 16; ++i) if (item->original_ip[i] != 0) nonzero = 1;
    if (!nonzero) return 0;
    if (item->family == 4) {
        for (i = 4; i < 16; ++i) if (item->original_ip[i] != 0) return 0;
    }
    return 1;
}
static int FbAuthEqual(const FbAuthOrigin* left, const FbAuthOrigin* right) {
    unsigned i;
    if (!left || !right ||
        left->pid != right->pid ||
        left->creation_100ns != right->creation_100ns ||
        left->process_start_key != right->process_start_key ||
        left->endpoint != right->endpoint ||
        left->flow_id != right->flow_id ||
        left->broker_pid != right->broker_pid ||
        left->family != right->family ||
        left->port_be != right->port_be) return 0;
    for (i = 0; i < 16; ++i)
        if (left->original_ip[i] != right->original_ip[i]) return 0;
    return 1;
}
static int FbAuthIssue(FbAuthBook* book, const FbAuthOrigin* item) {
    unsigned i;
    if (!book || book->lost || !FbAuthOriginValid(item)) {
        if (book) book->lost = 1;
        return 0;
    }
    /* WFP endpoint handles are scoped to an OS lifetime, not a durable
     * sequence ID. Reusing one within a session is terminal ambiguity. */
    for (i = 0; i < book->count; ++i) {
        if (book->slots[i].origin.endpoint == item->endpoint ||
            book->slots[i].origin.flow_id == item->flow_id) {
            book->lost = 1;
            return 0;
        }
    }
    if (book->count >= FB_AUTH_CAP) {
        book->lost = 1;
        return 0;
    }
    book->slots[book->count].origin = *item;
    book->slots[book->count].state = 1;
    ++book->count;
    return 1;
}
static int FbAuthConsumeInitial(FbAuthBook* book, const FbAuthOrigin* exact) {
    unsigned i, seen = 0, matchIndex = 0;
    if (!book || book->lost || !FbAuthOriginValid(exact)) return 0;
    for (i = 0; i < book->count; ++i) {
        if (book->slots[i].state != 1 ||
            !FbAuthEqual(&book->slots[i].origin, exact)) continue;
        ++seen;
        matchIndex = i;
    }
    if (seen != 1) {
        if (seen > 1) book->lost = 1;
        return 0;
    }
    book->slots[matchIndex].state = 2;
    return 1;
}
/* AUTH receives OS origin PID, endpoint, broker and original SOCKADDR, but
 * NOT the secret flow sequence. The sequence is only generated in our
 * CONNECT_REDIRECT path; the kernel's exact match is unique within this book.
 * Missing OS metadata is represented by zero and never matches a record.
 * A physical proxy SSH socket to an external destination never satisfies the
 * original redirected-loopback authorization and must not be auto-permitted.
 */
static int FbAuthConsumeObserved(FbAuthBook* book, const FbAuthOrigin* observed) {
    unsigned i, found = FB_AUTH_CAP;
    if (!book || book->lost || !observed || observed->flow_id != 0 ||
        !observed->pid || !observed->creation_100ns ||
        !observed->process_start_key || !observed->endpoint ||
        !observed->broker_pid || !observed->port_be ||
        (observed->family != 4 && observed->family != 6))
        return 0;
    for (i = 0; i < book->count; ++i) {
        FbAuthOrigin current = book->slots[i].origin;
        if (book->slots[i].state != 1) continue;
        current.flow_id = 0;
        if (!FbAuthEqual(&current, observed)) continue;
        if (found != FB_AUTH_CAP) { book->lost = 1; return 0; }
        found = i;
    }
    if (found == FB_AUTH_CAP) return 0;
    book->slots[found].state = 2;
    return 1;
}
static int FbAuthRetire(FbAuthBook* book, const FbAuthOrigin* exact) {
    unsigned i;
    if (!book || !FbAuthOriginValid(exact)) return 0;
    for (i = 0; i < book->count; ++i) {
        if (!FbAuthEqual(&book->slots[i].origin, exact)) continue;
        book->slots[i].state = 3;
        return 1;
    }
    return 0;
}
static int FbAuthProcessExit(FbAuthBook* book, FbUint64 pid,
                             FbUint64 creation_100ns, FbUint64 start_key) {
    unsigned i;
    if (!book || book->lost || !pid || !creation_100ns || !start_key)
        return 0;
    for (i = 0; i < book->count; ++i) {
        FbAuthSlot* slot = &book->slots[i];
        if (slot->origin.pid != pid) continue;
        if (slot->origin.creation_100ns != creation_100ns ||
            slot->origin.process_start_key != start_key) {
            book->lost = 1;
            return 0;
        }
        slot->state = 3;
    }
    return 1;
}
#endif
