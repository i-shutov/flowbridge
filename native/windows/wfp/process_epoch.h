#ifndef FLOWBRIDGE_WFP_PROCESS_EPOCH_H
#define FLOWBRIDGE_WFP_PROCESS_EPOCH_H
#include "wire_types.h"

/*
 * Fixed-storage process-incarnation registry for WFP ALE. This pure bounded
 * state machine is shared by the REAL WDK process-notify path and native
 * Windows negative tests. ALL mutations and lookups are performed under the
 * driver's existing spin lock; the helper NEVER writes or supplies entries.
 *
 * Process pointer tokens are used ONLY to disambiguate callbacks; they are
 * not dereferenced, exported to user mode or treated as network authority.
 * A process present before callback registration is NOT backfilled by a
 * user-mode PID snapshot: a missing identity must be blocked.
 */
#define FB_EPOCH_BUCKETS 512u
#define FB_EPOCH_WAYS 8u
#define FB_EPOCH_CAPACITY (FB_EPOCH_BUCKETS * FB_EPOCH_WAYS)
typedef struct FbEpochRecord {
    FbUint64 pid;
    FbUint64 creation_100ns;
    FbUint64 start_key;
    FbUint64 process_token;
} FbEpochRecord;
typedef struct FbEpochTable {
    FbEpochRecord entries[FB_EPOCH_CAPACITY];
    FbUint32 lost;
} FbEpochTable;

static unsigned FbEpochBucket(FbUint64 pid) {
    /* Windows PIDs are usually 4-aligned; mix after removing low zeros. */
    const FbUint64 mixed = (pid >> 2u) * 11400714819323198485ull;
    return (unsigned)(mixed >> 55u);
}
static int FbEpochValid(FbEpochRecord item) {
    return item.pid != 0 && item.creation_100ns != 0 &&
           item.start_key != 0 && item.process_token != 0;
}
static int FbEpochInsert(FbEpochTable* table, FbEpochRecord record) {
    unsigned bucket, i, firstFree = FB_EPOCH_CAPACITY;
    if (!table || table->lost || !FbEpochValid(record)) {
        if (table) table->lost = 1;
        return 0;
    }
    bucket = FbEpochBucket(record.pid) * FB_EPOCH_WAYS;
    for (i = 0; i < FB_EPOCH_WAYS; ++i) {
        FbEpochRecord* existing = &table->entries[bucket + i];
        if (existing->pid == record.pid) {
            /* No PID can have multiple live incarnations. Never overwrite. */
            table->lost = 1;
            return 0;
        }
        if (firstFree == FB_EPOCH_CAPACITY && existing->pid == 0)
            firstFree = bucket + i;
    }
    if (firstFree == FB_EPOCH_CAPACITY) {
        table->lost = 1; /* Hash bucket exhausted: fail CLOSED globally. */
        return 0;
    }
    table->entries[firstFree] = record;
    return 1;
}
static int FbEpochLookup(const FbEpochTable* table, FbUint64 pid, FbEpochRecord* out) {
    unsigned bucket, i;
    if (!table || !out || !pid || table->lost) return 0;
    bucket = FbEpochBucket(pid) * FB_EPOCH_WAYS;
    for (i = 0; i < FB_EPOCH_WAYS; ++i) {
        const FbEpochRecord* current = &table->entries[bucket + i];
        if (current->pid == pid && FbEpochValid(*current)) {
            *out = *current;
            return 1;
        }
    }
    return 0;
}
static int FbEpochExit(FbEpochTable* table, FbEpochRecord record) {
    unsigned bucket, i;
    if (!table || !FbEpochValid(record)) return 0;
    bucket = FbEpochBucket(record.pid) * FB_EPOCH_WAYS;
    for (i = 0; i < FB_EPOCH_WAYS; ++i) {
        FbEpochRecord* current = &table->entries[bucket + i];
        if (current->pid != record.pid) continue;
        if (current->creation_100ns != record.creation_100ns ||
            current->start_key != record.start_key ||
            current->process_token != record.process_token) {
            table->lost = 1;
            return 0;
        }
        current->pid = current->creation_100ns =
            current->start_key = current->process_token = 0;
        return 1;
    }
    /* Processes already running before notifier registration never entered
     * this ledger; their exit is not an integrity failure. */
    return 0;
}
#endif
