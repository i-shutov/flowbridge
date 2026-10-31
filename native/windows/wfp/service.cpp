#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
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
#include "control.h"
#include "listener_owner.hpp"
#include "../profile_integrity.hpp"
#include "flowbridge.h"
#include "nlohmann/json.hpp"
using Json=nlohmann::json;
namespace {
constexpr wchar_t ServiceName[]=L"FlowBridgeCapture";
std::atomic<bool> stopping{false};
SERVICE_STATUS_HANDLE statusHandle=nullptr;
std::mutex statusLock, logLock;
std::wstring profilePath, sshProfilePath;
std::vector<std::wstring> bypassPaths, capturePaths;
DWORD guiOwnerPid=0;
std::wstring guiStopName;
std::string guiProfileSha256;
// The lifetime guard is optional in service/console developer mode. It is
// mandatory for a GUI-owned elevated helper, including UAC race and GUI crash.
class GuiLifetime {
    HANDLE owner_=nullptr, stop_=nullptr;
    std::thread monitor_;
public:
    GuiLifetime() {
        if(!guiOwnerPid)return;
        if(guiStopName.rfind(L"Local\\FlowBridgeCaptureStop-",0)!=0 || guiStopName.size()>128)
            throw std::runtime_error("Invalid GUI capture stop event");
        owner_=OpenProcess(SYNCHRONIZE,FALSE,guiOwnerPid);
        stop_=OpenEventW(SYNCHRONIZE,FALSE,guiStopName.c_str());
        if(!owner_||!stop_){if(owner_)CloseHandle(owner_);if(stop_)CloseHandle(stop_);owner_=stop_=nullptr;
            throw std::runtime_error("Capture GUI owner or stop event is unavailable");}
        monitor_=std::thread([this]{
            while(!stopping) {
                if(WaitForSingleObject(owner_,0)!=WAIT_TIMEOUT ||
                   WaitForSingleObject(stop_,0)!=WAIT_TIMEOUT){stopping=true;return;}
                Sleep(50);
            }
        });
    }
    ~GuiLifetime(){stopping=true;if(monitor_.joinable())monitor_.join();
        if(stop_)CloseHandle(stop_);if(owner_)CloseHandle(owner_);}
};
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
void handle(SOCKET raw,uint64_t nativeSession,uint64_t idleMs) noexcept {
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
        auto result=response(fb_native_stream_open_wfp_json(nativeSession,flow.dump().c_str(),records.data(),length));
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
std::string readConfiguration(const std::wstring& path) {
    std::ifstream input(std::filesystem::path(path),std::ios::binary);
    if(!input || std::filesystem::file_size(path)>1024*1024) throw std::runtime_error("SSH profile unavailable or exceeds 1 MiB");
    std::string value((std::istreambuf_iterator<char>(input)),{});
    if(input.bad() || value.size()>1024*1024 || value.find('\0')!=std::string::npos) throw std::runtime_error("Invalid SSH profile file");
    return value;
}
std::wstring wideUtf8(const std::string& value) {
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0);
    if(!n) throw std::runtime_error("Invalid SSH executable path");
    std::wstring out(n,0);
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),out.data(),n);
    return out;
}
struct OwnedSSH {
    uint64_t id=0;
    ~OwnedSSH(){if(id)fb_ssh_destroy(id);}
    Json snapshot(){return id?response(fb_ssh_snapshot_json(id)):Json::object();}
};
struct OwnedNative {
    uint64_t id=0;
    ~OwnedNative(){if(id)fb_native_destroy(id);}
    void stop(){if(id){fb_native_destroy(id);id=0;}}
};
void run() {
    std::ifstream input(std::filesystem::path(profilePath),std::ios::binary);
    if(!input || std::filesystem::file_size(profilePath)>1024*1024) throw std::runtime_error("Profile unavailable or exceeds 1 MiB");
    std::string config((std::istreambuf_iterator<char>(input)),{});
    if(input.bad() || config.size()>1024*1024 || config.find('\0')!=std::string::npos) throw std::runtime_error("Invalid profile file");
    if(guiOwnerPid &&
       !profile_integrity::identical(guiProfileSha256,profile_integrity::sha256(config)))
        throw std::runtime_error("GUI native profile SHA-256 mismatch across UAC; refusing elevated capture");
    response(fb_validate_json(config.c_str()));
    auto j=Json::parse(config);
    std::string guiListenerHost;
    unsigned short guiListenerPort=0;
    if(guiOwnerPid) {
        for(const auto& proxy:j.at("proxies")) {
            if(proxy.at("id")!="gui-owned-socks")continue;
            if(guiListenerPort || proxy.at("kind")!="socks5")
                throw std::runtime_error("Invalid GUI-owned SOCKS route");
            guiListenerHost=proxy.at("endpoint").at("host").get<std::string>();
            const auto port=proxy.at("endpoint").at("port").get<unsigned int>();
            if(port==0||port>65535)
                throw std::runtime_error("GUI-owned SOCKS listener port is invalid");
            guiListenerPort=static_cast<unsigned short>(port);
        }
    }
    auto idleMs=j.value("idle_timeout_ms",uint64_t(300000));
    // Beta uses bounded native workers. The shared Rust budget also counts
    // opening/waiting flows and holds its permit until stream destruction.
    size_t max=std::min<size_t>(128,j.value("max_connections",size_t(128)));
    if(!max) throw std::runtime_error("Zero maximum connections");
    OwnedSSH ssh; OwnedNative native;
    Json nativeOptions=Json::object();
    if(!sshProfilePath.empty()) {
        auto sshConfig=readConfiguration(sshProfilePath);
        ssh.id=response(fb_ssh_create_json(sshConfig.c_str())).at("ssh_id").get<uint64_t>();
        response(fb_ssh_start_json(ssh.id));
        auto deadline=GetTickCount64()+45000;
        Json status;
        while(!stopping) {
            status=ssh.snapshot().at("status");
            auto state=status.value("state",std::string());
            if(state=="ready")break;
            if(state=="failed" || GetTickCount64()>=deadline)throw std::runtime_error("SSH failed to become ready; capture was not enabled");
            Sleep(50);
        }
        if(stopping)return;
        if(!status.contains("backend_path") || !status["backend_path"].is_string())throw std::runtime_error("SSH executable identity unavailable; refusing capture recursion risk");
        bypassPaths.push_back(wideUtf8(status["backend_path"].get<std::string>()));
        nativeOptions={{"managed_endpoint",{{"host","127.0.0.1"},{"port",status.at("local_port")}}},
                       {"ready",true},{"ready_lease_ms",5000},{"pause_grace_ms",30000}};
    }
    native.id=response(fb_native_create_json(config.c_str(),nativeOptions.dump().c_str())).at("session_id").get<uint64_t>();
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
                handle(socket,native.id,idleMs);
                {std::lock_guard<std::mutex> guard(lock); --admitted;}
            }
        });
        // Before WFP captures any selected application, check the Windows
        // TCP owner table. A different process must not impersonate the
        // unelevated GUI's SOCKS listener on its loopback port.
        if(guiListenerPort &&
           !listener_owner::ownedBy(guiListenerHost,guiListenerPort,guiOwnerPid))
            throw std::runtime_error("GUI-owned SOCKS listener is not bound by the expected FlowBridge GUI process");
        if(!stopping) capture.start(p4,p6,bypassPaths,capturePaths);
        if(!stopping) {report(SERVICE_RUNNING); log({{"event","ready"},{"capture","tcp_ipv4_ipv6"},{"workers",max},{"selected_executables",capturePaths.size()},{"gui_listener_os_owner_verified",guiListenerPort!=0}});}
        auto lastSnapshot=GetTickCount64();
        auto lastOwnerCheck=GetTickCount64();
        while(!stopping) {
            if(guiListenerPort && GetTickCount64()-lastOwnerCheck>=500) {
                lastOwnerCheck=GetTickCount64();
                if(!listener_owner::ownedBy(guiListenerHost,guiListenerPort,guiOwnerPid))
                    throw std::runtime_error("GUI-owned SOCKS listener disappeared or changed PID; native WFP capture withdrawn");
            }
            if(ssh.id) {
                auto observed=ssh.snapshot();
                const auto state=observed.at("status").value("state",std::string());
                auto gate=Json{{"ready",state=="ready"}}.dump();
                response(fb_native_set_gate_json(native.id,gate.c_str()));
            }
            if(GetTickCount64()-lastSnapshot>=1000) {
                auto report=response(fb_native_snapshot_json(native.id));
                report["event"]="native_status";log(report);lastSnapshot=GetTickCount64();
            }
            fd_set set; FD_ZERO(&set); FD_SET(l4.value,&set); FD_SET(l6.value,&set); timeval wait{0,200000};
            int n=select(0,&set,nullptr,nullptr,&wait); if(n==SOCKET_ERROR) throw std::runtime_error("Listener select failed");
            for(SOCKET listenSocket:{l4.value,l6.value}) if(FD_ISSET(listenSocket,&set)) {
                SOCKET accepted=accept(listenSocket,nullptr,nullptr);
                if(accepted==INVALID_SOCKET) {if(WSAGetLastError()==WSAEWOULDBLOCK) continue; throw std::runtime_error("Listener accept failed");}
                std::lock_guard<std::mutex> guard(lock);
                if(admitted>=max) closesocket(accepted); else {queue.push_back(accepted); ++admitted; cv.notify_one();}
            }
        }
        capture.stop(); fb_native_destroy(native.id); finish(); native.id=0;
    } catch(...) {stopping=true; capture.stop(); fb_native_destroy(native.id); finish(); native.id=0; throw;}
}
void WINAPI serviceMain(DWORD,wchar_t**) {
    statusHandle=RegisterServiceCtrlHandlerExW(ServiceName,control,nullptr);
    if(!statusHandle) return;
    report(SERVICE_START_PENDING);
    try {GuiLifetime lifetime;run();report(SERVICE_STOPPED);}
    catch(const std::exception& e) {log({{"event","faulted"},{"error",e.what()}});report(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR);}
}
}
int wmain(int argc,wchar_t** argv) {
    bool console=false,service=false;
    try {
        if(argc==2 && std::wstring(argv[1])==L"--preflight") {
            // Read-only device query; presence is not interception acceptance.
            HANDLE driver=CreateFileW(FB_WFP_DEVICE,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
            DWORD code=driver==INVALID_HANDLE_VALUE?GetLastError():0;
            bool valid=false;
            if(driver!=INVALID_HANDLE_VALUE){
                FbWfpStatus info{};DWORD got=0;
                valid=DeviceIoControl(driver,FB_IOCTL_QUERY,nullptr,0,&info,sizeof(info),&got,nullptr)
                    && got==sizeof(info)&&info.size==sizeof(info)&&info.version==FB_WFP_ABI;
                if(!valid)code=GetLastError();CloseHandle(driver);
            }
            std::cout<<Json{{"product","FlowBridgeCapture"},{"native_helper",true},
                 {"kernel_driver_accessible",valid},{"driver_error_code",code},
                 {"redirect_runtime_tested",false},{"driver_auto_installed",false}}.dump()<<std::endl;
            return 0;
        }
        for(int i=1;i<argc;++i) {
            std::wstring arg=argv[i];
            if(arg==L"--console") console=true;
            else if(arg==L"--service") service=true;
            else if(arg==L"--profile" && i+1<argc) profilePath=argv[++i];
            else if(arg==L"--ssh-profile" && i+1<argc) sshProfilePath=argv[++i];
            else if(arg==L"--capture-app" && i+1<argc) capturePaths.emplace_back(argv[++i]);
            else if(arg==L"--gui-owner" && i+1<argc) {
                auto value=std::wstring(argv[++i]);
                if(value.empty()||!std::all_of(value.begin(),value.end(),[](wchar_t c){return c>=L'0'&&c<=L'9';}))
                    throw std::runtime_error("Invalid GUI owner process ID");
                auto number=std::stoull(value);
                if(number==0||number>0xffffffffULL)throw std::runtime_error("Invalid GUI process ID");
                guiOwnerPid=static_cast<DWORD>(number);
            }
            else if(arg==L"--stop-event" && i+1<argc) guiStopName=argv[++i];
            else if(arg==L"--profile-sha256" && i+1<argc) {
                const auto hash=std::wstring(argv[++i]);
                if(hash.size()!=64 ||
                   !std::all_of(hash.begin(),hash.end(),[](wchar_t c){
                       return (c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f');
                   })) throw std::runtime_error("Invalid profile SHA-256");
                guiProfileSha256.assign(hash.begin(),hash.end());
            }
            else if(arg==L"--bypass" && i+1<argc) bypassPaths.emplace_back(argv[++i]);
            else throw std::runtime_error("Usage: FlowBridgeCapture --console|--service --profile ABSOLUTE_PATH --capture-app ABSOLUTE_EXE_PATH [--capture-app ...] [--ssh-profile ABSOLUTE_PATH] [--bypass ABSOLUTE_EXE_PATH]...");
        }
        if((guiOwnerPid==0)!=guiStopName.empty())throw std::runtime_error("GUI owner and stop event must be provided together");
        if(service&&guiOwnerPid)throw std::runtime_error("SCM-managed helper cannot accept a GUI owner");
        // A UAC-elevated helper must not start OpenSSH or read private identity
        // files using the elevated token for an unelevated GUI owner. The GUI
        // runs SSH in its original user session and supplies only a loopback
        // SOCKS endpoint; standalone developer/service mode is separate.
        if(guiOwnerPid&&!sshProfilePath.empty())
            throw std::runtime_error("GUI-owned capture must reuse the unelevated SSH session; --ssh-profile is forbidden");
        if(guiOwnerPid && !profile_integrity::valid(guiProfileSha256))
            throw std::runtime_error("GUI capture requires an exact profile SHA-256");
        if(!guiOwnerPid && !guiProfileSha256.empty())
            throw std::runtime_error("Profile SHA-256 belongs to GUI-owned capture only");
        if(console==service || profilePath.empty() || !std::filesystem::path(profilePath).is_absolute()) throw std::runtime_error("Choose one run mode and an absolute administrator-controlled profile path");
        if(capturePaths.empty() || capturePaths.size()>64) throw std::runtime_error("Select 1..64 capture executables with --capture-app; whole-machine capture is not implicit");
        for(const auto& p:capturePaths) if(!std::filesystem::path(p).is_absolute() || !std::filesystem::is_regular_file(p)) throw std::runtime_error("Capture executable must be an existing absolute path");
        if(!sshProfilePath.empty() && !std::filesystem::path(sshProfilePath).is_absolute())throw std::runtime_error("SSH profile path must be absolute");
        for(const auto& p:bypassPaths) if(!std::filesystem::path(p).is_absolute()) throw std::runtime_error("Bypass executable path must be absolute");
        wchar_t self[32768]{}; DWORD length=GetModuleFileNameW(nullptr,self,32768);
        if(!length || length>=32768) throw std::runtime_error("Service executable identity unavailable");
        bypassPaths.emplace_back(self,length);
        if(console) {SetConsoleCtrlHandler(consoleControl,TRUE);GuiLifetime lifetime;run();return 0;}
        SERVICE_TABLE_ENTRYW table[]={{const_cast<wchar_t*>(ServiceName),serviceMain},{nullptr,nullptr}};
        if(!StartServiceCtrlDispatcherW(table)) throw std::runtime_error("SCM dispatcher failed: "+std::to_string(GetLastError()));
        return 0;
    } catch(const std::exception& e) {log({{"event","faulted"},{"error",e.what()}});return 1;}
}
