#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <atomic>
#include <array>
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "capture.h"
#include "redirect_io.h"
#include "flowbridge.h"
#include "nlohmann/json.hpp"
using Json=nlohmann::json;
namespace {
constexpr wchar_t ServiceName[]=L"FlowBridgeCapture";
std::atomic<bool> stopping{false};
SERVICE_STATUS_HANDLE statusHandle=nullptr;
std::mutex statusLock, logLock;
std::wstring profilePath;
std::vector<std::wstring> bypassPaths;
void log(const Json& event) noexcept {
    try { std::lock_guard<std::mutex> guard(logLock); auto line=event.dump()+"\n";
        std::cerr<<line; OutputDebugStringA(line.c_str()); } catch (...) {}
}
void report(DWORD state, DWORD error=0) {
    std::lock_guard<std::mutex> guard(statusLock);
    if (!statusHandle || (state==SERVICE_RUNNING && stopping.load())) return;
    SERVICE_STATUS s{}; s.dwServiceType=SERVICE_WIN32_OWN_PROCESS; s.dwCurrentState=state;
    s.dwControlsAccepted=state==SERVICE_RUNNING ? SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN : 0;
    s.dwWin32ExitCode=error; s.dwWaitHint=35000;
    if (state==SERVICE_START_PENDING || state==SERVICE_STOP_PENDING) s.dwCheckPoint=1;
    SetServiceStatus(statusHandle,&s);
}
DWORD WINAPI control(DWORD code,DWORD,void*,void*) {
    if (code==SERVICE_CONTROL_STOP || code==SERVICE_CONTROL_SHUTDOWN) { stopping=true; report(SERVICE_STOP_PENDING); }
    else if (code!=SERVICE_CONTROL_INTERROGATE) return ERROR_CALL_NOT_IMPLEMENTED;
    return NO_ERROR;
}
BOOL WINAPI consoleControl(DWORD code) {
    if (code==CTRL_C_EVENT || code==CTRL_BREAK_EVENT || code==CTRL_CLOSE_EVENT) { stopping=true; return TRUE; }
    return FALSE;
}
struct Socket {
    SOCKET value=INVALID_SOCKET;
    Socket()=default; explicit Socket(SOCKET s):value(s){}
    ~Socket(){if(value!=INVALID_SOCKET) closesocket(value);}
    Socket(const Socket&)=delete; Socket& operator=(const Socket&)=delete;
};
Json response(char* value) {
    if (!value) throw std::runtime_error("Core returned no response");
    std::unique_ptr<char,decltype(&fb_string_free)> owned(value,fb_string_free);
    Json j=Json::parse(value); if(!j.value("ok",false)) throw std::runtime_error(j.value("error",std::string("Core operation failed"))); return j;
}
std::string utf8(const uint16_t* text,size_t length) {
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,reinterpret_cast<const wchar_t*>(text),static_cast<int>(length),nullptr,0,nullptr,nullptr);
    if(!n) throw std::runtime_error("Invalid kernel UTF-16 executable identity");
    std::string result(n,0); WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,reinterpret_cast<const wchar_t*>(text),static_cast<int>(length),result.data(),n,nullptr,nullptr); return result;
}
// Nonblocking sockets plus select avoid retrying an operation after a Winsock
// send timeout with uncertain partial-consumption semantics.
bool ready(SOCKET socket,bool writing) {
    fd_set set; FD_ZERO(&set); FD_SET(socket,&set); timeval wait{0,200000};
    int n=select(0,writing?nullptr:&set,writing?&set:nullptr,nullptr,&wait);
    if(n==SOCKET_ERROR) throw std::runtime_error("Socket select failed");
    return n>0;
}
struct Stream { uint64_t id=0; ~Stream(){if(id) fb_stream_close(id);} };
void relay(SOCKET socket,uint64_t id,uint64_t idleMs) {
    std::atomic<bool> failed{false}; std::atomic<ULONGLONG> last{GetTickCount64()};
    auto cancelled=[&]{
        const auto observed=last.load(); // sample before clock: no unsigned race underflow
        return stopping.load() || failed.load() || GetTickCount64()-observed>idleMs;
    };
    std::thread upload([&]{
        try {
            std::array<uint8_t,32768> buffer{};
            while(!cancelled()) {
                if(!ready(socket,false)) continue;
                int count=recv(socket,reinterpret_cast<char*>(buffer.data()),static_cast<int>(buffer.size()),0);
                if(count==0) { if(fb_stream_shutdown_write(id)<0) failed=true; return; }
                if(count<0) { if(WSAGetLastError()==WSAEWOULDBLOCK) continue; throw std::runtime_error("Client receive failed"); }
                size_t offset=0;
                while(offset<static_cast<size_t>(count) && !cancelled()) {
                    auto n=fb_stream_write(id,buffer.data()+offset,static_cast<size_t>(count)-offset);
                    if(n==-2) continue;
                    if(n<=0) throw std::runtime_error("Upstream write failed");
                    offset+=static_cast<size_t>(n); last=GetTickCount64();
                }
            }
        } catch (...) { failed=true; }
    });
    try {
        std::array<uint8_t,32768> buffer{};
        while(!cancelled()) {
            auto count=fb_stream_read(id,buffer.data(),buffer.size());
            if(count==-2) continue;
            if(count<0) throw std::runtime_error("Upstream read failed");
            if(count==0) {shutdown(socket,SD_SEND); break;}
            size_t offset=0;
            while(offset<static_cast<size_t>(count) && !cancelled()) {
                if(!ready(socket,true)) continue;
                int n=send(socket,reinterpret_cast<char*>(buffer.data()+offset),static_cast<int>(count-offset),0);
                if(n<0 && WSAGetLastError()==WSAEWOULDBLOCK) continue;
                if(n<=0) throw std::runtime_error("Client send failed");
                offset+=static_cast<size_t>(n); last=GetTickCount64();
            }
        }
    } catch (...) {failed=true;}
    // Preserve upload after upstream half-close until its EOF/idle deadline.
    upload.join();
}
void handle(SOCKET raw,const std::string& config,uint64_t idleMs) noexcept {
    Socket socket(raw); FbRedirectContext context{};
    try {
        std::array<uint8_t,65536> records{}; uint32_t length=0;
        int error=fb_wfp_query(raw,&context,records.data(),static_cast<uint32_t>(records.size()),&length);
        if(error) throw std::runtime_error("Missing/invalid WFP context or records: "+std::to_string(error));
        if(context.ipv6_scope_id) throw std::runtime_error("Scoped IPv6 destinations are not supported by the core endpoint ABI");
        auto path=utf8(context.process_path,context.process_path_chars);
        auto split=path.find_last_of("\\/"); auto application=path.substr(split==std::string::npos?0:split+1);
        if(application.empty()) throw std::runtime_error("Empty executable basename");
        char address[INET6_ADDRSTRLEN]{};
        if(!InetNtopA(context.address_family,context.destination_address,address,sizeof(address))) throw std::runtime_error("Original endpoint conversion failed");
        Json flow={{"application",application},{"destination",{{"host",address},{"port",ntohs(context.destination_port_be)}}},{"resolved_ip",address}};
        // Core copies records and sets them on EVERY outbound socket before
        // connect, including direct routes and first proxy-hop retry sockets.
        auto result=response(fb_stream_open_wfp_json(config.c_str(),flow.dump().c_str(),records.data(),length));
        Stream stream{result.at("stream_id").get<uint64_t>()};
        if(stopping) return;
        u_long nonblocking=1;
        if(ioctlsocket(raw,FIONBIO,&nonblocking)!=0) throw std::runtime_error("Nonblocking client setup failed");
        log({{"event","connected"},{"flow_id",context.flow_id},{"pid",context.original_process_id},{"kernel_path",path},{"flow",flow},{"decision",result.at("decision")}});
        relay(raw,stream.id,idleMs);
        log({{"event","closed"},{"flow_id",context.flow_id}});
    } catch (const std::exception& e) {log({{"event","rejected"},{"flow_id",context.flow_id},{"error",e.what()}});}
    catch (...) {log({{"event","rejected"},{"error","Unexpected native failure"}});}
}
SOCKET listener(int family,unsigned short& port) {
    Socket socket(::socket(family,SOCK_STREAM,IPPROTO_TCP));
    if(socket.value==INVALID_SOCKET) throw std::runtime_error("Listener socket creation failed");
    BOOL exclusive=TRUE;
    if(setsockopt(socket.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<char*>(&exclusive),sizeof(exclusive))) throw std::runtime_error("Listener exclusivity failed");
    sockaddr_storage address{}; int length=0;
    if(family==AF_INET) {auto p=reinterpret_cast<sockaddr_in*>(&address); p->sin_family=AF_INET; p->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*p);}
    else {DWORD only6=1; if(setsockopt(socket.value,IPPROTO_IPV6,IPV6_V6ONLY,reinterpret_cast<char*>(&only6),sizeof(only6))) throw std::runtime_error("IPv6 listener setup failed"); auto p=reinterpret_cast<sockaddr_in6*>(&address); p->sin6_family=AF_INET6; p->sin6_addr=in6addr_loopback; length=sizeof(*p);}
    if(bind(socket.value,reinterpret_cast<sockaddr*>(&address),length) || listen(socket.value,128) || getsockname(socket.value,reinterpret_cast<sockaddr*>(&address),&length)) throw std::runtime_error("Bind/listen failed");
    port=family==AF_INET?reinterpret_cast<sockaddr_in*>(&address)->sin_port:reinterpret_cast<sockaddr_in6*>(&address)->sin6_port;
    u_long nonblocking=1; if(ioctlsocket(socket.value,FIONBIO,&nonblocking)) throw std::runtime_error("Listener mode failed");
    SOCKET result=socket.value; socket.value=INVALID_SOCKET; return result;
}
void run() {
    std::ifstream input(std::filesystem::path(profilePath),std::ios::binary);
    if(!input || std::filesystem::file_size(profilePath)>1024*1024) throw std::runtime_error("Profile unavailable or exceeds 1 MiB");
    std::string config((std::istreambuf_iterator<char>(input)),{});
    if(input.bad() || config.size()>1024*1024 || config.find('\0')!=std::string::npos) throw std::runtime_error("Invalid profile file");
    response(fb_validate_json(config.c_str()));
    auto j=Json::parse(config);
    auto idleMs=j.value("idle_timeout_ms",uint64_t(300000));
    // Bounded resources: up to 32 workers plus one upload thread per active flow.
    size_t max=std::min<size_t>(32,j.value("max_connections",size_t(32)));
    if(!max) throw std::runtime_error("Zero maximum connections");
    WSADATA wsa{}; if(WSAStartup(MAKEWORD(2,2),&wsa)) throw std::runtime_error("Winsock startup failed");
    struct Cleanup {~Cleanup(){WSACleanup();}} cleanup;
    unsigned short p4=0,p6=0; Socket l4(listener(AF_INET,p4)),l6(listener(AF_INET6,p6));
    std::mutex lock; std::condition_variable cv; std::deque<SOCKET> queue; bool ending=false; size_t admitted=0;
    std::vector<std::thread> workers;
    auto finish=[&]{ {std::lock_guard<std::mutex> guard(lock); ending=true; for(auto s:queue) closesocket(s); queue.clear();} cv.notify_all(); for(auto& t:workers) if(t.joinable()) t.join(); };
    Capture capture;
    try {
        for(size_t i=0;i<max;++i) workers.emplace_back([&]{
            for(;;) {SOCKET socket;
                {std::unique_lock<std::mutex> guard(lock); cv.wait(guard,[&]{return ending || !queue.empty();}); if(ending) return; socket=queue.front();queue.pop_front();}
                handle(socket,config,idleMs);
                {std::lock_guard<std::mutex> guard(lock); --admitted;}
            }
        });
        if(!stopping) capture.start(p4,p6,bypassPaths);
        if(!stopping) {report(SERVICE_RUNNING); log({{"event","ready"},{"capture","tcp_ipv4_ipv6"},{"workers",max}});}
        while(!stopping) {
            fd_set set; FD_ZERO(&set); FD_SET(l4.value,&set); FD_SET(l6.value,&set); timeval wait{0,200000};
            int n=select(0,&set,nullptr,nullptr,&wait); if(n==SOCKET_ERROR) throw std::runtime_error("Listener select failed");
            for(SOCKET listenSocket:{l4.value,l6.value}) if(FD_ISSET(listenSocket,&set)) {
                SOCKET accepted=accept(listenSocket,nullptr,nullptr);
                if(accepted==INVALID_SOCKET) {if(WSAGetLastError()==WSAEWOULDBLOCK) continue; throw std::runtime_error("Listener accept failed");}
                std::lock_guard<std::mutex> guard(lock);
                if(admitted>=max) closesocket(accepted); else {queue.push_back(accepted); ++admitted; cv.notify_one();}
            }
        }
        capture.stop(); finish();
    } catch(...) {stopping=true; capture.stop(); finish(); throw;}
}
void WINAPI serviceMain(DWORD,wchar_t**) {
    statusHandle=RegisterServiceCtrlHandlerExW(ServiceName,control,nullptr);
    if(!statusHandle) return;
    report(SERVICE_START_PENDING);
    try {run();report(SERVICE_STOPPED);}
    catch(const std::exception& e) {log({{"event","faulted"},{"error",e.what()}});report(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR);}
}
}
int wmain(int argc,wchar_t** argv) {
    bool console=false,service=false;
    try {
        for(int i=1;i<argc;++i) {
            std::wstring arg=argv[i];
            if(arg==L"--console") console=true;
            else if(arg==L"--service") service=true;
            else if(arg==L"--profile" && i+1<argc) profilePath=argv[++i];
            else if(arg==L"--bypass" && i+1<argc) bypassPaths.emplace_back(argv[++i]);
            else throw std::runtime_error("Usage: FlowBridgeCapture --console|--service --profile ABSOLUTE_PATH [--bypass ABSOLUTE_EXE_PATH]...");
        }
        if(console==service || profilePath.empty() || !std::filesystem::path(profilePath).is_absolute()) throw std::runtime_error("Choose one run mode and an absolute administrator-controlled profile path");
        for(const auto& p:bypassPaths) if(!std::filesystem::path(p).is_absolute()) throw std::runtime_error("Bypass executable path must be absolute");
        wchar_t self[32768]{}; DWORD length=GetModuleFileNameW(nullptr,self,32768);
        if(!length || length>=32768) throw std::runtime_error("Service executable identity unavailable");
        bypassPaths.emplace_back(self,length);
        if(console) {SetConsoleCtrlHandler(consoleControl,TRUE);run();return 0;}
        SERVICE_TABLE_ENTRYW table[]={{const_cast<wchar_t*>(ServiceName),serviceMain},{nullptr,nullptr}};
        if(!StartServiceCtrlDispatcherW(table)) throw std::runtime_error("SCM dispatcher failed: "+std::to_string(GetLastError()));
        return 0;
    } catch(const std::exception& e) {log({{"event","faulted"},{"error",e.what()}});return 1;}
}
