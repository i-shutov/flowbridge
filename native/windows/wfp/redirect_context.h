#ifndef FLOWBRIDGE_REDIRECT_CONTEXT_H
#define FLOWBRIDGE_REDIRECT_CONTEXT_H
#include <stdint.h>
/* Version 2 copies the WFP ALE_APP_ID at classify time. No user-mode PID lookup
 * is used: the captured path remains valid after exit/PID reuse. UTF-16 uses
 * uint16_t so C, C++, Rust and WDK agree. No pointers or guessed DNS names. */
#define FB_REDIRECT_MAGIC 0x46425243u
#define FB_REDIRECT_VERSION 2u
#define FB_PROCESS_PATH_CHARS 1024u
#define FB_REDIRECT_CONTEXT_BYTES 2112u
typedef struct FbRedirectContext {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint64_t original_process_id;
    uint64_t flow_id;
    uint16_t address_family;
    uint16_t destination_port_be;
    uint8_t destination_address[16];
    uint32_t ipv6_scope_id;
    uint16_t process_path_chars; /* excludes terminator, 1..1023 */
    uint8_t reserved[14];
    uint16_t process_path[FB_PROCESS_PATH_CHARS]; /* NUL + zero tail */
} FbRedirectContext;
#ifdef __cplusplus
static_assert(sizeof(FbRedirectContext) == FB_REDIRECT_CONTEXT_BYTES, "Redirect ABI drift");
#endif
#endif
