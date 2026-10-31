// Test the production full-path/TCP selector against the real BFE. A terminating
// BLOCK at AUTH_CONNECT proves scope without loading our redirect driver.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <rpc.h>
#include <iostream>
#include <string>
#include "../native/windows/wfp/app_scope.h"

struct Handle {
    HANDLE value=nullptr;
    ~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
struct Engine {
    HANDLE value=nullptr;
    ~Engine(){if(value)FwpmEngineClose0(value);}
};
struct Socket {
    SOCKET value=INVALID_SOCKET;
    ~Socket(){if(value!=INVALID_SOCKET)closesocket(value);}
};
void check(DWORD error,const char* operation){
    if(error)throw std::runtime_error(std::string(operation)+": "+std::to_string(error));
}
int hold(const wchar_t* path,const wchar_t* stopName,const wchar_t* ownerText){
    ApplicationId application(path); // Fail before opening/modifying WFP.
    Handle stop{OpenEventW(SYNCHRONIZE,FALSE,stopName)};
    Handle owner{OpenProcess(SYNCHRONIZE,FALSE,std::stoul(ownerText))};
    if(!stop.value || !owner.value)throw std::runtime_error("Test lifetime handles unavailable");
    Engine engine;
    FWPM_SESSION0 session{};session.flags=FWPM_SESSION_FLAG_DYNAMIC;
    check(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&session,&engine.value),"Open test BFE session");
    GUID key{};const auto uuid=UuidCreate(&key);
    if(uuid!=RPC_S_OK && uuid!=RPC_S_UUID_LOCAL_ONLY)check(uuid,"Create test key");
    check(FwpmTransactionBegin0(engine.value,0),"Begin test transaction");
    FWPM_SUBLAYER0 layer{};layer.subLayerKey=key;layer.weight=0x100;
    layer.displayData.name=const_cast<wchar_t*>(L"FlowBridge isolated EXE scope QA");
    check(FwpmSubLayerAdd0(engine.value,&layer,nullptr),"Add test sublayer");
    auto conditions=application.tcpConditions();
    for(const GUID& id:{FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWPM_LAYER_ALE_AUTH_CONNECT_V6}){
        FWPM_FILTER0 filter{};filter.layerKey=id;filter.subLayerKey=key;
        filter.displayData.name=const_cast<wchar_t*>(L"FlowBridge QA: selected temporary EXE only");
        filter.action.type=FWP_ACTION_BLOCK;filter.weight.type=FWP_EMPTY;
        filter.numFilterConditions=static_cast<UINT32>(conditions.size());
        filter.filterCondition=conditions.data();
        check(FwpmFilterAdd0(engine.value,&filter,nullptr,nullptr),"Add test app filter");
    }
    check(FwpmTransactionCommit0(engine.value),"Commit test filters");
    std::cout<<"{\"ready\":true,\"driver_loaded\":false,\"layer\":\"ALE_AUTH_CONNECT\"}"<<std::endl;
    HANDLE events[]={stop.value,owner.value};
    const auto result=WaitForMultipleObjects(2,events,FALSE,120000);
    if(result==WAIT_FAILED)check(GetLastError(),"Wait test lifetime");
    if(result==WAIT_TIMEOUT)throw std::runtime_error("Test lifetime exceeded 120 seconds");
    return 0; // Dynamic session deletion is also tested after TerminateProcess.
}
int probe(const wchar_t* host,const wchar_t* portText,const wchar_t* protocol){
    const int family=std::wstring(host)==L"::1"?AF_INET6:AF_INET;
    if(std::wstring(host)!=L"::1" && std::wstring(host)!=L"127.0.0.1")throw std::runtime_error("Loopback QA only");
    const bool udp=std::wstring(protocol)==L"udp";
    if(!udp && std::wstring(protocol)!=L"tcp")throw std::runtime_error("Invalid test protocol");
    auto port=std::stoul(portText);if(!port || port>65535)throw std::runtime_error("Invalid port");
    Socket socket{::socket(family,udp?SOCK_DGRAM:SOCK_STREAM,udp?IPPROTO_UDP:IPPROTO_TCP)};
    if(socket.value==INVALID_SOCKET)check(static_cast<DWORD>(WSAGetLastError()),"Socket");
    sockaddr_storage address{};int length=0;
    if(family==AF_INET){auto* a=reinterpret_cast<sockaddr_in*>(&address);a->sin_family=AF_INET;a->sin_port=htons(static_cast<u_short>(port));a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);length=sizeof(*a);}
    else {auto* a=reinterpret_cast<sockaddr_in6*>(&address);a->sin6_family=AF_INET6;a->sin6_port=htons(static_cast<u_short>(port));a->sin6_addr=in6addr_loopback;length=sizeof(*a);}
    u_long nonblocking=1;check(static_cast<DWORD>(ioctlsocket(socket.value,FIONBIO,&nonblocking)),"Set nonblocking");
    int error=0;
    if(connect(socket.value,reinterpret_cast<sockaddr*>(&address),length)==SOCKET_ERROR){
        error=WSAGetLastError();
        if(error==WSAEWOULDBLOCK){
            fd_set writable,failed;FD_ZERO(&writable);FD_ZERO(&failed);FD_SET(socket.value,&writable);FD_SET(socket.value,&failed);
            timeval timeout{4,0};const int count=select(0,nullptr,&writable,&failed,&timeout);
            if(count<=0)throw std::runtime_error("Probe connect deadline or select error");
            int bytes=sizeof(error);check(static_cast<DWORD>(getsockopt(socket.value,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&bytes)),"Connect status");
        }
    }
    if(error){std::cout<<"{\"connect_error\":"<<error<<"}"<<std::endl;return error==WSAEACCES?13:2;}
    nonblocking=0;check(static_cast<DWORD>(ioctlsocket(socket.value,FIONBIO,&nonblocking)),"Set blocking");
    DWORD timeout=4000;
    check(static_cast<DWORD>(setsockopt(socket.value,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))),"Read deadline");
    check(static_cast<DWORD>(setsockopt(socket.value,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))),"Write deadline");
    const std::string payload="FlowBridge scope probe";
    if(send(socket.value,payload.data(),static_cast<int>(payload.size()),0)!=static_cast<int>(payload.size()))throw std::runtime_error("Probe send failed");
    if(!udp)shutdown(socket.value,SD_SEND);
    std::string answer;char buffer[128];
    while(answer.size()<payload.size()){
        const int count=recv(socket.value,buffer,sizeof(buffer),0);
        if(count<=0)throw std::runtime_error("Probe receive failed");
        answer.append(buffer,static_cast<size_t>(count));
    }
    if(answer!=payload)throw std::runtime_error("Probe payload changed");
    std::cout<<"{\"connected\":true,\"echo_verified\":true}"<<std::endl;return 0;
}
int wmain(int argc,wchar_t** argv){
    WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))return 2;
    struct Cleanup{~Cleanup(){WSACleanup();}} cleanup;
    try{
        if(argc==5 && std::wstring(argv[1])==L"hold")return hold(argv[2],argv[3],argv[4]);
        if(argc==5 && std::wstring(argv[1])==L"probe")return probe(argv[2],argv[3],argv[4]);
        throw std::runtime_error("Expected hold EXE STOP_EVENT OWNER_PID or probe LOOPBACK PORT tcp|udp");
    }catch(const std::exception& error){std::cerr<<error.what()<<std::endl;return 2;}
}
