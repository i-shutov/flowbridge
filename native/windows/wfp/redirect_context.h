#ifndef FLOWBRIDGE_REDIRECT_CONTEXT_H
#define FLOWBRIDGE_REDIRECT_CONTEXT_H
#include "wire_types.h"
/* Version 2 copies WFP ALE_APP_ID at classify time. Identity remains valid
 * after process exit/PID reuse. UTF-16 and all offsets match the Rust decoder. */
#define FB_REDIRECT_MAGIC 0x46425243u
#define FB_REDIRECT_VERSION 2u
#define FB_PROCESS_PATH_CHARS 1024u
#define FB_REDIRECT_CONTEXT_BYTES 2112u
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
} FbRedirectContext;
#ifdef __cplusplus
static_assert(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES, "Redirect ABI drift");
#endif
#endif
