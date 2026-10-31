#include "redirect_io.h"
#include <mstcpip.h>
// Windows SDK mstcpip.h socket IOCTLs (absent in older MinGW SDKs).
#ifndef SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS
#define SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS _WSAIOW(IOC_VENDOR, 220)
#define SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT _WSAIOW(IOC_VENDOR, 221)
#define SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS _WSAIOW(IOC_VENDOR, 222)
#endif
#include <cstring>
#include <cstddef>
static_assert(offsetof(FbRedirectContext, original_process_id) == 8, "ABI offset");
static_assert(offsetof(FbRedirectContext, destination_address) == 28, "ABI offset");
namespace {
constexpr DWORD Limit = 65536;
bool zeros(const uint8_t* p, size_t count) {
    for (size_t i=0;i<count;++i) if (p[i]) return false;
    return true;
}
}
extern "C" int fb_wfp_query(SOCKET accepted, FbRedirectContext *context,
                             void *records, uint32_t capacity, uint32_t *records_size) {
    if (!context || !records || !records_size || capacity < sizeof(ULONG) || capacity > Limit) return WSAEINVAL;
    *records_size = 0;
    std::memset(context,0,sizeof(*context));
    FbRedirectContext candidate{};
    DWORD count=0;
    if (WSAIoctl(accepted,SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,nullptr,0,
                 &candidate,sizeof(candidate),&count,nullptr,nullptr)==SOCKET_ERROR) return WSAGetLastError();
    if (count!=sizeof(candidate) || candidate.magic!=FB_REDIRECT_MAGIC ||
        candidate.version!=FB_REDIRECT_VERSION || candidate.size!=sizeof(candidate) ||
        !candidate.original_process_id || !candidate.destination_port_be ||
        !candidate.process_path_chars || candidate.process_path_chars >= FB_PROCESS_PATH_CHARS ||
        !zeros(candidate.reserved,sizeof(candidate.reserved))) return WSAEINVAL;
    if (candidate.address_family==AF_INET) {
        if (candidate.ipv6_scope_id || !zeros(candidate.destination_address+4,12)) return WSAEINVAL;
    } else if (candidate.address_family!=AF_INET6) return WSAEAFNOSUPPORT;
    for (uint16_t i=0;i<candidate.process_path_chars;++i)
        if (candidate.process_path[i]<32) return WSAEINVAL;
    if (!zeros(reinterpret_cast<const uint8_t*>(candidate.process_path+candidate.process_path_chars),
               (FB_PROCESS_PATH_CHARS-candidate.process_path_chars)*sizeof(uint16_t))) return WSAEINVAL;
    count=0;
    if (WSAIoctl(accepted,SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,nullptr,0,
                 records,capacity,&count,nullptr,nullptr)==SOCKET_ERROR) return WSAGetLastError();
    if (count==0 || count>capacity) return WSAEINVAL;
    *context=candidate; *records_size=count;
    return 0;
}
extern "C" int fb_wfp_set_records(SOCKET outbound, const void *records, uint32_t count) {
    if (!records || count==0 || count>Limit) return WSAEINVAL;
    DWORD returned=0;
    if (WSAIoctl(outbound,SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
                 const_cast<void*>(records),count,nullptr,0,&returned,nullptr,nullptr)==SOCKET_ERROR) return WSAGetLastError();
    return 0;
}
