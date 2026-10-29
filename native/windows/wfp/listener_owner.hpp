#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// A GUI-owned user-level listener is identified by the OS TCP table, not by
// trusting an arbitrary loopback process claiming to implement SOCKS5.
// This is a fail-closed ownership check (not cryptographic IPC authentication).
namespace listener_owner {
inline std::vector<std::uint8_t> table(int family) {
    DWORD required=0;
    DWORD code=GetExtendedTcpTable(nullptr,&required,FALSE,family,
                                   TCP_TABLE_OWNER_PID_LISTENER,0);
    if(code!=ERROR_INSUFFICIENT_BUFFER)
        throw std::runtime_error("Query TCP listener ownership size failed: "+std::to_string(code));
    constexpr DWORD MaxTable=8*1024*1024;
    for(int attempt=0;attempt<3;++attempt) {
        if(required<sizeof(DWORD)||required>MaxTable)
            throw std::runtime_error("Unexpected TCP listener table size");
        // Pad to tolerate listener churn while GetExtendedTcpTable fills data.
        std::vector<std::uint8_t> bytes(required+4096);
        DWORD capacity=static_cast<DWORD>(bytes.size());
        code=GetExtendedTcpTable(bytes.data(),&capacity,FALSE,family,
                                 TCP_TABLE_OWNER_PID_LISTENER,0);
        if(code==NO_ERROR) {
            bytes.resize(capacity);
            return bytes;
        }
        if(code!=ERROR_INSUFFICIENT_BUFFER)
            throw std::runtime_error("Query TCP listener ownership failed: "+std::to_string(code));
        required=capacity;
    }
    throw std::runtime_error("TCP listener table changed repeatedly during ownership check");
}
inline bool ownedBy(const std::string& host,unsigned short port,DWORD pid) {
    if(!pid||!port) return false;
    if(host=="127.0.0.1") {
        const auto bytes=table(AF_INET);
        const auto* rows=reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(bytes.data());
        const std::size_t offset=offsetof(MIB_TCPTABLE_OWNER_PID,table);
        if(bytes.size()<offset||rows->dwNumEntries>(bytes.size()-offset)/sizeof(MIB_TCPROW_OWNER_PID))
            throw std::runtime_error("Invalid IPv4 listener table length");
        for(DWORD i=0;i<rows->dwNumEntries;++i) {
            const auto& row=rows->table[i];
            if(row.dwState==MIB_TCP_STATE_LISTEN &&
               row.dwOwningPid==pid && row.dwLocalAddr==htonl(INADDR_LOOPBACK) &&
               ntohs(static_cast<u_short>(row.dwLocalPort))==port)
                return true;
        }
        return false;
    }
    if(host=="::1") {
        const auto bytes=table(AF_INET6);
        const auto* rows=reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(bytes.data());
        const std::size_t offset=offsetof(MIB_TCP6TABLE_OWNER_PID,table);
        if(bytes.size()<offset||rows->dwNumEntries>(bytes.size()-offset)/sizeof(MIB_TCP6ROW_OWNER_PID))
            throw std::runtime_error("Invalid IPv6 listener table length");
        constexpr std::array<unsigned char,16> loopback={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        for(DWORD i=0;i<rows->dwNumEntries;++i) {
            const auto& row=rows->table[i];
            if(row.dwState==MIB_TCP_STATE_LISTEN &&
               row.dwOwningPid==pid &&
               std::memcmp(row.ucLocalAddr,loopback.data(),loopback.size())==0 &&
               ntohs(static_cast<u_short>(row.dwLocalPort))==port)
                return true;
        }
        return false;
    }
    throw std::runtime_error("GUI-owned SOCKS listener must be a literal IPv4/IPv6 loopback address");
}
} // namespace listener_owner
