#pragma once
#include <winsock2.h>
#include "redirect_context.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Caller owns sockets, calls WSAStartup, supplies synchronous accepted TCP socket.
 * Return 0 on success; otherwise Winsock/Win32 error. Never fall back to direct.
 * Query verifies exact context v2 and copies opaque records into caller storage.
 * Allocate records_capacity=65536. On failure outputs must not be used.
 */
int fb_wfp_query(SOCKET accepted, FbRedirectContext *context,
                 void *records, uint32_t records_capacity, uint32_t *records_size);
/* Call before connect() on EVERY outbound socket for the flow, including first
 * proxy hop and retry sockets. Records are opaque and must not be interpreted.
 */
int fb_wfp_set_records(SOCKET unconnected_outbound, const void *records, uint32_t records_size);
#ifdef __cplusplus
}
#endif
