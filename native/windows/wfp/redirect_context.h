#ifndef FLOWBRIDGE_REDIRECT_CONTEXT_H
#define FLOWBRIDGE_REDIRECT_CONTEXT_H
#include "wire_types.h"
/* V3: copies OS ALE_APP_ID and authenticated birth/start-key from the
 * kernel process-creation callback's bounded live ledger. Identity remains
 * immutable on the accepted socket, not from a post-hoc PID/tuple snapshot.
 * This is not yet native G2/no-DIRECT acceptance. */
#define FB_REDIRECT_MAGIC 0x46425243u
#define FB_REDIRECT_VERSION 3u
#define FB_PROCESS_PATH_CHARS 1024u
#define FB_REDIRECT_CONTEXT_BYTES 2136u
typedef struct FbRedirectContext {
    FbUint32 magic;
    FbUint16 version;
    FbUint16 size;
    FbUint64 original_process_id;
    FbUint64 flow_id;
    FbUint16 address_family;
    FbUint16 destination_port_be;
    FbUint8 destination_address[16];
    FbUint32 ipv6_scope_id;
    FbUint16 process_path_chars;
    FbUint8 reserved[14];
    FbUint16 process_path[FB_PROCESS_PATH_CHARS];
    FbUint64 original_process_creation_100ns;
    FbUint64 original_process_start_key;
    FbUint64 original_transport_endpoint;
} FbRedirectContext;
#ifdef __cplusplus
static_assert(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES, "Redirect ABI drift");
#endif
#endif
