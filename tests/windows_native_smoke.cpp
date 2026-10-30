// Real Win32 ABI/UI integration. Run ONLY in a disposable Windows user or Wine
// prefix: the GUI intentionally persists a test profile in that user's AppData.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <chrono>
#include <cstdio>
#include <functional>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include "flowbridge.h"
#include "nlohmann/json.hpp"
#include "../native/windows/native_profile.hpp"
#include "../native/windows/capture_launcher.hpp"
#include "../native/windows/ssh_pool_policy.hpp"
#include "../native/windows/wfp/listener_owner.hpp"

using Json = nlohmann::json;
using namespace std::chrono_literals;
static void need(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
static void waitFor(const std::function<bool()>& predicate, const char* message) {
    auto until = std::chrono::steady_clock::now() + 8s;
    while (!predicate()) { need(std::chrono::steady_clock::now() < until, message); std::this_thread::sleep_for(25ms); }
}
struct Socket {
    SOCKET value=INVALID_SOCKET;
    Socket() = default;
    explicit Socket(SOCKET s):value(s) { need(s!=INVALID_SOCKET,"socket failed"); DWORD timeout=3000; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout)); setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout)); }
    ~Socket() { if(value!=INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&)=delete;
    Socket& operator=(const Socket&)=delete;
};
static unsigned short listenOn(Socket& s) {
    s.value=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); need(s.value!=INVALID_SOCKET,"listener socket failed");
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    need(bind(s.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"listener bind failed");
    need(listen(s.value,8)==0,"listen failed"); int length=sizeof(address);
    need(getsockname(s.value,reinterpret_cast<sockaddr*>(&address),&length)==0,"getsockname failed"); return ntohs(address.sin_port);
}
static unsigned short unusedPort() { Socket s; return listenOn(s); }
static void sendAll(SOCKET s,const char* data,int length) { while(length) { int n=send(s,data,length,0); need(n>0,"send failed"); data+=n; length-=n; } }
static std::string receive(SOCKET s,int length) { std::string data(length,'\0'); int offset=0; while(offset<length) { int n=recv(s,data.data()+offset,length-offset,0); need(n>0,"unexpected EOF/read failure"); offset+=n; } return data; }
static Json result(char* value) {
    need(value!=nullptr,"FFI null response"); std::unique_ptr<char,decltype(&fb_string_free)> owned(value,fb_string_free);
    Json json=Json::parse(value); if(!json.value("ok",false)) throw std::runtime_error(json.value("error",std::string("FFI error"))); return json;
}
static Json config(unsigned short port) { return Json{{"version",1},{"listen","127.0.0.1:"+std::to_string(port)},{"proxies",Json::array()},{"chains",Json::array()},{"rules",Json::array()},{"default_action",{{"type","direct"}}},{"connect_timeout_ms",2000},{"handshake_timeout_ms",2000},{"idle_timeout_ms",10000},{"max_connections",16}}; }
static void transfer(unsigned short port) {
    Socket listener; unsigned short target=listenOn(listener); Socket client(socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(port);
    need(connect(client.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"SOCKS listener unavailable");
    const char hello[]={5,1,0}; sendAll(client.value,hello,3); need(receive(client.value,2)==std::string("\5\0",2),"SOCKS negotiation mismatch");
    const char request[]={5,1,0,1,127,0,0,1,static_cast<char>(target>>8),static_cast<char>(target&255)};
    sendAll(client.value,request,10); auto reply=receive(client.value,10); need(reply[0]==5&&reply[1]==0,"SOCKS CONNECT failed");
    Socket peer(accept(listener.value,nullptr,nullptr));
    const std::string upload("binary\0payload\xff",15), download("final\0response",14);
    sendAll(client.value,upload.data(),static_cast<int>(upload.size())); need(receive(peer.value,static_cast<int>(upload.size()))==upload,"upload mismatch");
    shutdown(client.value,SD_SEND); char byte{}; need(recv(peer.value,&byte,1,0)==0,"upload half-close was not propagated");
    sendAll(peer.value,download.data(),static_cast<int>(download.size())); shutdown(peer.value,SD_SEND);
    need(receive(client.value,static_cast<int>(download.size()))==download,"download mismatch"); need(recv(client.value,&byte,1,0)==0,"download EOF missing");
}
static std::wstring windowText(HWND h) { int n=static_cast<int>(SendMessageW(h,WM_GETTEXTLENGTH,0,0)); std::wstring value(n+1,L'\0'); SendMessageW(h,WM_GETTEXT,n+1,reinterpret_cast<LPARAM>(value.data())); value.resize(n); return value; }
static void edit(HWND h,const std::string& value) { std::wstring w(value.begin(),value.end()); need(SendMessageW(h,WM_SETTEXT,0,reinterpret_cast<LPARAM>(w.c_str()))!=0,"set editor failed"); }
static void click(HWND h,int id) { SendMessageW(h,WM_COMMAND,MAKEWPARAM(id,BN_CLICKED),reinterpret_cast<LPARAM>(GetDlgItem(h,id))); }
static void abiTest() {
    unsigned short port=unusedPort(); auto profile=config(port).dump(); auto id=result(fb_engine_create_json(profile.c_str())).at("engine_id").get<uint64_t>();
    try {
        result(fb_engine_start_json(id)); transfer(port);
        waitFor([&]{ return result(fb_engine_snapshot_json(id))["status"]["active"]==0; },"ABI flow did not finish");
        auto snapshot=result(fb_engine_snapshot_json(id)); need(snapshot["status"]["bytes_up"]==15&&snapshot["status"]["bytes_down"]==14,"ABI byte metrics mismatch");
        auto invalid=config(port); invalid["listen"]="0.0.0.0:1081";
        char* raw=fb_engine_reload_json(id,invalid.dump().c_str()); need(raw!=nullptr,"reload null"); Json rejected=Json::parse(raw); fb_string_free(raw); need(rejected["ok"]==false,"unsafe reload accepted");
        need(result(fb_engine_snapshot_json(id))["status"]["generation"]==1,"failed reload replaced profile");
        result(fb_engine_stop_json(id)); result(fb_engine_start_json(id)); result(fb_engine_stop_json(id));
        fb_engine_destroy(id); std::puts("PASS Windows DLL: traffic, binary payload, half-close, metrics, reload rollback, restart");
    } catch (...) { fb_engine_destroy(id); throw; }
}
static void captureWindow(HWND window,const std::filesystem::path& path) {
    SetForegroundWindow(window);RedrawWindow(window,nullptr,nullptr,RDW_INVALIDATE|RDW_UPDATENOW|RDW_ALLCHILDREN);std::this_thread::sleep_for(150ms);
    RECT client{};GetClientRect(window,&client);HDC source=GetDC(window),target=CreateCompatibleDC(source);
    BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=client.right;info.bmiHeader.biHeight=-client.bottom;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
    void* pixels=nullptr;HBITMAP bitmap=CreateDIBSection(source,&info,DIB_RGB_COLORS,&pixels,nullptr,0);need(bitmap!=nullptr,"screenshot bitmap failed");auto prior=SelectObject(target,bitmap);
    need(BitBlt(target,0,0,client.right,client.bottom,source,0,0,SRCCOPY|CAPTUREBLT)!=0,"native screenshot copy failed");
    BITMAPFILEHEADER header{};header.bfType=0x4d42;header.bfOffBits=sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER);header.bfSize=header.bfOffBits+client.right*client.bottom*4;
    std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(&header),sizeof(header));out.write(reinterpret_cast<const char*>(&info.bmiHeader),sizeof(info.bmiHeader));out.write(static_cast<const char*>(pixels),client.right*client.bottom*4);out.close();
    SelectObject(target,prior);DeleteObject(bitmap);DeleteDC(target);ReleaseDC(window,source);need(out.good(),"native screenshot write failed");
}
static void nativeTemplateTest(){
    auto profile=config(1081);profile["proxies"]={{{"id","ssh"},{"kind","socks5"},{"endpoint",{{"host","127.0.0.1"},{"port",1080}}},{"username",nullptr},{"password_env",nullptr}}};
    auto exported=native_profile::build(profile,{"C:\\Apps\\Claude.exe","C:\\Browser\\chrome.exe","C:\\Other\\CLAUDE.EXE"},"ssh",false);result(fb_validate_json(exported.dump().c_str()));
    need(exported["rules"][0]["applications"].size()==2,"native export did not deduplicate basenames");need(exported["default_action"]["type"]=="direct","native template default must be Direct");
    Json flow={{"application","claude.exe"},{"destination",{{"host","unknown-new-ai-endpoint.example"},{"port",443}}},{"resolved_ip",nullptr}};
    auto routed=result(fb_evaluate_json(exported.dump().c_str(),flow.dump().c_str()));need(routed["decision"]["action"]["type"]=="proxy","selected app unknown domain escaped proxy");
    flow["application"]="other.exe";auto other=result(fb_evaluate_json(exported.dump().c_str(),flow.dump().c_str()));need(other["decision"]["action"]["type"]=="direct","unselected app did not use Direct");
    auto blocked=native_profile::build(profile,{"C:\\Apps\\Claude.exe"},"ssh",true);need(blocked["default_action"]["type"]=="block","explicit block-other option missing");
    auto dnsPolicy=exported;dnsPolicy["remote_dns_via_ssh"]=false;
    result(fb_validate_json(dnsPolicy.dump().c_str()));
    flow["application"]="claude.exe";flow["destination"]["host"]="uncached.example";
    auto denied=result(fb_evaluate_json(dnsPolicy.dump().c_str(),flow.dump().c_str()));
    need(denied["decision"]["action"]["type"]=="block",
         "Unchecked SSH DNS mode let a hostname reach proxy or DIRECT");
    flow["destination"]["host"]="192.0.2.10";
    auto literal=result(fb_evaluate_json(dnsPolicy.dump().c_str(),flow.dump().c_str()));
    need(literal["decision"]["action"]["type"]=="proxy",
         "Unchecked SSH DNS mode incorrectly blocked numeric IP traffic");
    dnsPolicy["remote_dns_via_ssh"]="false";
    char* invalidDns=fb_validate_json(dnsPolicy.dump().c_str());
    need(invalidDns!=nullptr,"Invalid DNS policy returned null");
    const auto invalidAnswer=Json::parse(invalidDns);fb_string_free(invalidDns);
    need(invalidAnswer.value("ok",true)==false,"String DNS preference unexpectedly accepted");
    std::puts("PASS native template export: basenames, deduplication, selected unknown hosts via proxy, other apps Direct, optional Block");
}
static void nativeGuiListenerOwnerTest() {
    Socket v4;
    const auto port=listenOn(v4);
    const auto pid=GetCurrentProcessId();
    need(listener_owner::ownedBy("127.0.0.1",port,pid),
         "Windows TCP owner table did not attest the current GUI listener");
    need(!listener_owner::ownedBy("127.0.0.1",port,pid+1),
         "Windows TCP owner table accepted a different process as SOCKS owner");
    need(!listener_owner::ownedBy("127.0.0.1",port==1?2:1,pid),
         "Windows TCP owner table accepted a different port");
    bool rejected=false;
    try {listener_owner::ownedBy("0.0.0.0",port,pid);}
    catch(const std::exception&) {rejected=true;}
    need(rejected,"Non-loopback listener was accepted for privileged WFP routing");
    Socket v6(socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP));
    sockaddr_in6 address{};address.sin6_family=AF_INET6;
    address.sin6_addr=in6addr_loopback;
    DWORD only6=1;need(setsockopt(v6.value,IPPROTO_IPV6,IPV6_V6ONLY,
        reinterpret_cast<const char*>(&only6),sizeof(only6))==0,"IPv6-only listener setup");
    need(bind(v6.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0 &&
         listen(v6.value,8)==0,"IPv6 test listener failed");
    int length=sizeof(address);
    need(getsockname(v6.value,reinterpret_cast<sockaddr*>(&address),&length)==0,
         "IPv6 test listener port unavailable");
    need(listener_owner::ownedBy("::1",ntohs(address.sin6_port),pid),
         "Windows IPv6 TCP owner table did not attest the current GUI listener");
    need(!listener_owner::ownedBy("::1",ntohs(address.sin6_port),pid+1),
         "Windows IPv6 listener ownership incorrectly trusted an unrelated PID");
    std::puts("PASS Windows TCP ownership: IPv4/IPv6 loopback, exact PID and port, unsafe bind rejected");
}
static void nativeUnelevatedSshProfileTest() {
    auto source=config(1081);
    source["proxies"]={{{"id","managed-ssh"},{"kind","socks5"},
                       {"endpoint",{{"host","127.0.0.1"},{"port",1080}}},
                       {"username",nullptr},{"password_env","FLOWBRIDGE_TEST_SECRET"}}};
    const auto isolated=native_profile::viaUserOwnedSsh(source,{R"(C:\AI\Claude.exe)"});
    const auto dumped=isolated.dump();
    result(fb_validate_json(dumped.c_str()));
    need(isolated["proxies"].size()==1&&isolated["chains"].empty(),
         "Elevated helper retained unrelated proxy routes or chains");
    need(isolated["proxies"][0]["id"]=="gui-owned-socks" &&
         isolated["proxies"][0]["endpoint"]["host"]=="127.0.0.1" &&
         isolated["proxies"][0]["endpoint"]["port"]==1081,
         "Native helper does not target the user-owned engine listener");
    need(isolated["listen"]=="127.0.0.1:1","Unbound WFP-only profile listener mismatch");
    need(dumped.find("FLOWBRIDGE_TEST_SECRET")==std::string::npos &&
         dumped.find("managed-ssh")==std::string::npos,
         "Privileged helper still receives user-mode SSH credentials/configuration");
    Json flow={{"application","claude.exe"},
               {"destination",{{"host","uncached.example"},{"port",443}}},
               {"resolved_ip",nullptr}};
    auto proxy=result(fb_evaluate_json(dumped.c_str(),flow.dump().c_str()));
    need(proxy["decision"]["action"]["type"]=="proxy" &&
         proxy["decision"]["action"]["id"]=="gui-owned-socks",
         "Selected app did not use the user-owned SSH/SOCKS engine");
    flow["application"]="not-selected.exe";
    need(result(fb_evaluate_json(dumped.c_str(),flow.dump().c_str()))["decision"]["action"]["type"]=="direct",
         "Unselected app unexpectedly captured by private helper policy");
    auto expectReject=[&](const std::string& listen) {
        auto bad=source;bad["listen"]=listen;bool rejected=false;
        try {native_profile::viaUserOwnedSsh(bad,{"app.exe"});}
        catch(const std::exception&) {rejected=true;}
        need(rejected,"Unsafe/non-loopback GUI SOCKS listener accepted");
    };
    for(const auto& listen:{"0.0.0.0:1081","127.0.0.1:0","127.0.0.1:65536",
                             "127.0.0.1:abc","hostname.example:1081","[::]:1081"})
        expectReject(listen);
    auto ipv6=source;ipv6["listen"]="[::1]:1082";
    const auto v6=native_profile::viaUserOwnedSsh(ipv6,{"app.exe"});
    result(fb_validate_json(v6.dump().c_str()));
    need(v6["proxies"][0]["endpoint"]["host"]=="::1" &&
         v6["proxies"][0]["endpoint"]["port"]==1082,
         "IPv6 user-owned local SOCKS endpoint was rewritten unsafely");
    std::puts("PASS native GUI-owned SSH: local listener only, no privileged secrets/routes, selected policy, IPv6 and fail-closed validation");
}
static void nativeLauncherArgumentTest() {
    wchar_t module[32768]{};DWORD count=GetModuleFileNameW(nullptr,module,32768);
    need(count&&count<32768,"test helper path unavailable");
    auto testApp=std::wstring(module,count);
    const auto event=L"Local\\FlowBridgeCaptureStop-{12345678-1234-1234-1234-123456789012}";
    const auto digest=profile_integrity::sha256("abc");
    need(digest=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         "Windows SHA-256 interoperability with standard crypto is broken");
    need(profile_integrity::identical(digest,digest)&&
         !profile_integrity::identical(digest,std::string(64,'0')),
         "Native SHA-256 comparison failed");
    auto params=capture_launcher::arguments(L"C:\\Users\\Test User\\profile.json",L"",{testApp},42,event,{},digest);
    need(params.find(L"--gui-owner 42")!=std::wstring::npos,"GUI lifetime argument missing");
    need(params.find(L"--capture-app ")!=std::wstring::npos,"Selected process path missing");
    need(params.find(L"--stop-event ")!=std::wstring::npos,"Stop event argument missing");
    need(params.find(L"--profile-sha256 ")!=std::wstring::npos,
         "Launcher did not pin profile bytes across UAC");
    need(params.find(L"--ssh-profile")==std::wstring::npos,
         "GUI-owned native capture unexpectedly forwards SSH secrets into UAC");
    wchar_t systemDirectory[MAX_PATH]{};
    const UINT directoryChars=GetSystemDirectoryW(systemDirectory,MAX_PATH);
    need(directoryChars&&directoryChars<MAX_PATH,"System directory path unavailable");
    const auto bypassExe=(std::filesystem::path(systemDirectory)/L"cmd.exe").wstring();
    need(std::filesystem::is_regular_file(bypassExe),"Windows cmd.exe unavailable");
    const auto withBypass=capture_launcher::arguments(
        LR"(C:\Users\Test User\profile.json)",L"",{testApp},42,event,{bypassExe},digest);
    need(withBypass.find(L"--bypass ")!=std::wstring::npos &&
         withBypass.find(L"--ssh-profile")==std::wstring::npos,
         "GUI/SSH process identity bypass or unprivileged SSH boundary missing");
    bool selfBypassRejected=false;
    try {
        capture_launcher::arguments(LR"(C:\profile.json)",L"",{testApp},42,event,{testApp},digest);
    } catch(const std::exception&) { selfBypassRejected=true; }
    need(selfBypassRejected,"Selected executable was silently bypassed at the WFP layer");
    bool invalidBypass=false;
    try {
        capture_launcher::arguments(LR"(C:\profile.json)",L"",{testApp},42,event,{L"relative-ssh.exe"},digest);
    } catch(const std::exception&) { invalidBypass=true; }
    need(invalidBypass,"Relative SSH backend bypass accepted");
    need(capture_launcher::quote(L"C:\\A B\\") == L"\"C:\\A B\\\\\"", "Windows backslash quoting incorrect");
    bool rejected=false;
    try {capture_launcher::arguments(L"relative.json",L"",{testApp},42,event,{},digest);} catch(const std::exception&) {rejected=true;}
    need(rejected,"Relative elevated configuration accepted");
    rejected=false;
    try {capture_launcher::arguments(L"C:\\profile.json",L"",{L"relative.exe"},42,event,{},digest);} catch(const std::exception&) {rejected=true;}
    need(rejected,"Relative capture executable accepted");
    bool missingHashRejected=false;
    try {capture_launcher::arguments(LR"(C:\profile.json)",L"",{testApp},42,event,{},"invalid");}
    catch(const std::exception&) {missingHashRejected=true;}
    need(missingHashRejected,"Launcher accepted missing/invalid GUI profile digest");
    std::puts("PASS native capture launcher: full-path selection, quoted parameters, GUI owner and validation");
}
// Use client coordinates rather than comparing screen rectangles. These
// assertions exercise actual Win32 child placement at the smallest supported
// desktop size instead of accepting a cropped screenshot as visual QA.
static RECT childBounds(HWND window,int id) {
    HWND child=GetDlgItem(window,id);
    need(child&&IsWindow(child),"Compact GUI control is missing");
    RECT rect{};need(GetWindowRect(child,&rect)!=0,"Cannot measure compact GUI child");
    MapWindowPoints(nullptr,window,reinterpret_cast<POINT*>(&rect),2);
    return rect;
}
static void assertCompactLayout(HWND window,const wchar_t* screenshot) {
    need(SetWindowPos(window,nullptr,0,0,980,680,SWP_NOMOVE|SWP_NOZORDER)!=0,
         "Could not resize the GUI to compact Windows desktop");
    // Bounds must be on the actual monitor work area, not merely inside a
    // BitBlt screenshot of an off-screen / cropped window DC.
    MONITORINFO monitor{sizeof(MONITORINFO)};
    need(GetMonitorInfoW(MonitorFromWindow(window,MONITOR_DEFAULTTONEAREST),&monitor)!=0,
         "Could not query native monitor work area");
    RECT outer{};
    need(GetWindowRect(window,&outer)!=0,"Cannot read actual GUI window bounds");
    need(outer.left>=monitor.rcWork.left-2&&outer.top>=monitor.rcWork.top-2&&
         outer.right<=monitor.rcWork.right+2&&outer.bottom<=monitor.rcWork.bottom+2,
         "Compact GUI extends outside monitor work area");
    // Query the running GUI window, not the harness' own (potentially
    // DPI-virtualized) GetDeviceCaps(LOGPIXELSX). This is actual OS DPI.
    const UINT dpi=GetDpiForWindow(window);
    need(dpi>=96&&dpi<=768,"Actual GUI window reported an invalid Win32 DPI");
    std::printf("FB_QA_WINDOW_DPI=%u\n",static_cast<unsigned>(dpi));
    RECT client{};GetClientRect(window,&client);
    need(client.right>=920&&client.bottom>=600,"Compact window minimum client area not reached");
    auto evidence=[&](const wchar_t* page) {
        if(!screenshot)return;
        const std::filesystem::path target(screenshot);
        const auto name=target.stem().wstring()+L"-compact-"+page+target.extension().wstring();
        captureWindow(window,target.parent_path()/name);
    };
    auto inside=[&](int id){
        auto r=childBounds(window,id);
        need(r.left>=0&&r.top>=0&&r.right<=client.right&&r.bottom<=client.bottom,
             "Compact GUI child lies outside the viewport");
        return r;
    };
    click(window,200);
    const auto connections=inside(110);
    const auto dashboardHelp=inside(209);
    need(connections.bottom+6<=dashboardHelp.top,"Dashboard connection list obscures help");
    evidence(L"dashboard");
    click(window,201);
    HWND mode=GetDlgItem(window,230);
    SendMessageW(mode,CB_SETCURSEL,1,0);
    SendMessageW(window,WM_COMMAND,MAKEWPARAM(230,CBN_SELCHANGE),reinterpret_cast<LPARAM>(mode));
    need(IsWindowVisible(GetDlgItem(window,2010))&&
         IsWindowVisible(GetDlgItem(window,2015))&&
         IsWindowVisible(GetDlgItem(window,243)),
         "Managed SSH labels or help disappeared when switching modes");
    const auto sshHelp=inside(243);
    const auto save=inside(240);
    const auto sshExe=inside(286);
    const auto browseSsh=inside(287);
    const auto compression=inside(237);
    const auto workerLabel=inside(2030);
    const auto workerCount=inside(288);
    need(IsWindowVisible(GetDlgItem(window,286))&&IsWindowVisible(GetDlgItem(window,287))&&
         IsWindowVisible(GetDlgItem(window,288)),
         "OpenSSH executable or worker count control missing on managed SSH page");
    need(compression.right+6<=workerLabel.left &&
         workerLabel.right<=workerCount.left &&
         workerCount.right+6<=sshExe.left &&
         sshExe.right+6<=browseSsh.left,
         "SSH worker pool, executable and Browse controls overlap at 980x680");
    const auto dnsToggle=inside(285);
    need(IsWindowVisible(GetDlgItem(window,285)),
         "Remote SSH DNS control was not shown for managed SSH");
    need(dnsToggle.right+8<=save.left,
         "Remote SSH DNS checkbox overlaps Save button at compact size");
    inside(246); // Last managed-SSH timeout field
    need(sshHelp.bottom+6<=save.top,"Managed SSH form overlaps Save button");
    evidence(L"ssh");
    SendMessageW(mode,CB_SETCURSEL,0,0);
    SendMessageW(window,WM_COMMAND,MAKEWPARAM(230,CBN_SELCHANGE),reinterpret_cast<LPARAM>(mode));
    need(IsWindowVisible(GetDlgItem(window,2000))&&
         IsWindowVisible(GetDlgItem(window,2003))&&
         !IsWindowVisible(GetDlgItem(window,243)),
         "External proxy labels or managed-SSH help were shown in the wrong mode");
    evidence(L"proxy");
    click(window,202);
    const auto preset=inside(264);
    const auto discover=inside(260);
    need(preset.right+6<=discover.left,"Application presets overlap the Discover button");
    const auto apps=inside(261);
    const auto hint=inside(2018);
    need(apps.bottom+6<=hint.top,"Application table overlaps its footer");
    const auto start=inside(282),stop=inside(283),exported=inside(266);
    need(start.right+6<=stop.left&&stop.right+6<=exported.left,
         "Native capture actions overlap at compact width");
    need(exported.bottom<=client.bottom,"Native capture actions are clipped");
    evidence(L"apps");
    click(window,203);
    inside(109);inside(111); // JSON editor and log
    evidence(L"advanced");
    click(window,200);
    // Opening the Applications page can launch the real bounded discovery
    // worker. Await its completion before the subsequent Apply/Start smoke:
    // otherwise the legitimate busy gate rejects Apply and causes a false
    // GUI regression unrelated to geometry.
    waitFor([&]{
        return IsWindowEnabled(GetDlgItem(window,100)) &&
               IsWindowEnabled(GetDlgItem(window,260));
    },"Compact layout triggered discovery which did not return to idle");
    std::puts("PASS compact Windows GUI: SSH, apps, native capture actions and diagnostics fit 980x680");
}
static void guiTest(const wchar_t* executable,const wchar_t* screenshot) {
    STARTUPINFOW start{}; start.cb=sizeof(start); PROCESS_INFORMATION process{};
    std::wstring command=L"\""+std::wstring(executable)+L"\"";
    need(CreateProcessW(executable,command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&start,&process)!=0,"GUI launch failed");
    HWND window=nullptr;
    try {
        need(WaitForInputIdle(process.hProcess,8000)==0,"GUI did not finish initialization");
        waitFor([&]{ window=FindWindowW(L"FlowBridgeNativeV02",nullptr); return window!=nullptr; },"GUI window did not appear");
        assertCompactLayout(window,screenshot);
        const int startId=100,stopId=101,applyId=102,proxyId=105,hostId=106,protocolId=108,editorId=109,tableId=110,statusId=112;
        const int modeId=230;SendMessageW(GetDlgItem(window,modeId),CB_SETCURSEL,0,0);SendMessageW(window,WM_COMMAND,MAKEWPARAM(modeId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,modeId)));
        need(IsWindow(GetDlgItem(window,231))&&IsWindow(GetDlgItem(window,234)),"structured SSH editor missing");
        click(window,201);need(IsWindowVisible(GetDlgItem(window,hostId)),"connection page did not show existing proxy controls");
        SendMessageW(GetDlgItem(window,modeId),CB_SETCURSEL,1,0);SendMessageW(window,WM_COMMAND,MAKEWPARAM(modeId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,modeId)));
        need(IsWindowVisible(GetDlgItem(window,231))&&!IsWindowVisible(GetDlgItem(window,hostId)),"managed SSH mode visibility failed");
        need(IsWindowVisible(GetDlgItem(window,286))&&IsWindow(GetDlgItem(window,287)),
             "Windows native SSH executable selector is missing");
        need(IsWindowVisible(GetDlgItem(window,285))&&
             SendMessageW(GetDlgItem(window,285),BM_GETCHECK,0,0)==BST_CHECKED,
             "Remote SSH DNS checkbox is not checked by default");
        edit(GetDlgItem(window,231),"test.example");
        edit(GetDlgItem(window,233),"testuser");
        edit(GetDlgItem(window,286),"ssh.exe");
        click(window,240);
        need(windowText(GetDlgItem(window,280)).find(L"абсолютным путём")!=std::wstring::npos,
             "Relative SSH binary path was accepted in Windows GUI");
        edit(GetDlgItem(window,286),"");
        wchar_t appData[32768]{};
        const DWORD appDataChars=GetEnvironmentVariableW(L"LOCALAPPDATA",appData,32768);
        need(appDataChars>0&&appDataChars<32768,"LOCALAPPDATA is unavailable");
        const auto desktopFile=std::filesystem::path(appData)/L"FlowBridge"/L"desktop-settings.json";
        auto savedDns=[&] {
            std::ifstream in(desktopFile,std::ios::binary);
            need(in.good(),"Desktop settings were not persisted");
            Json saved=Json::parse(in);
            return saved.value("remote_dns_via_ssh",true);
        };
        waitFor([&]{return IsWindowEnabled(GetDlgItem(window,285));},
                "Remote DNS checkbox did not become available after discovery");
        SendMessageW(GetDlgItem(window,285),BM_SETCHECK,BST_UNCHECKED,0);
        click(window,285);
        need(!savedDns(),"Unchecked remote DNS was not saved to desktop profile");
        HWND poolCount=GetDlgItem(window,288);
        need(IsWindowVisible(poolCount) &&
             SendMessageW(poolCount,CB_GETCURSEL,0,0)==0,
             "New desktop profile must select a single SSH worker by default");
        SendMessageW(poolCount,CB_SETCURSEL,1,0);
        click(window,240);
        auto savedWorkers=[&] {
            std::ifstream in(desktopFile,std::ios::binary);
            need(in.good(),"Desktop pool settings not persisted");
            Json saved=Json::parse(in);
            return saved.value("ssh_workers",0);
        };
        need(savedWorkers()==2,"Two SSH workers were not saved to desktop profile");
        SendMessageW(poolCount,CB_SETCURSEL,0,0);
        click(window,240);
        need(savedWorkers()==1,"Single-worker desktop setting was not restored");
        waitFor([&]{return IsWindowEnabled(GetDlgItem(window,285));},
                "Remote DNS checkbox remained busy");
        SendMessageW(GetDlgItem(window,285),BM_SETCHECK,BST_CHECKED,0);
        click(window,285);
        need(savedDns(),"Checked remote DNS was not restored in desktop profile");
        wchar_t currentExe[32768]{};
        need(GetModuleFileNameW(nullptr,currentExe,32768)>0, "Test executable path unavailable");
        const std::wstring explicitExe(currentExe);
        need(std::filesystem::path(explicitExe).is_absolute(), "Test path is not absolute");
        // This exe is NOT an OpenSSH client; it exercises only file picker
        // persistence, never launches the selected program as a tunnel.
        // SetWindowTextW is not allowed to set an EDIT control in another
        // application process. Use the same marshalled WM_SETTEXT message as
        // all other native GUI smoke input helpers.
        need(SendMessageW(GetDlgItem(window,286),WM_SETTEXT,0,
                          reinterpret_cast<LPARAM>(explicitExe.c_str()))!=0,
             "Optional SSH binary field refused cross-process WM_SETTEXT input");
        const auto observedExe=windowText(GetDlgItem(window,286));
        if(observedExe!=explicitExe){
            std::size_t first=0;
            while(first<std::min(observedExe.size(),explicitExe.size()) &&
                  observedExe[first]==explicitExe[first])++first;
            std::fprintf(stderr,
                "SSH exe field diagnosis: expected_utf16_units=%zu actual_utf16_units=%zu first_diff=%zu expected_cp=%u actual_cp=%u visible=%d enabled=%d\n",
                explicitExe.size(),observedExe.size(),first,
                first<explicitExe.size()?static_cast<unsigned>(explicitExe[first]):0,
                first<observedExe.size()?static_cast<unsigned>(observedExe[first]):0,
                IsWindowVisible(GetDlgItem(window,286))?1:0,
                IsWindowEnabled(GetDlgItem(window,286))?1:0);
        }
        need(observedExe==explicitExe,
             "Optional SSH binary edit control truncated or altered absolute path");
        const int utf8Bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,
            explicitExe.data(),static_cast<int>(explicitExe.size()),nullptr,0,nullptr,nullptr);
        need(utf8Bytes>0,"UTF-8 SSH executable test path invalid");
        std::string expectedUtf8(static_cast<size_t>(utf8Bytes),'\0');
        need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,
             explicitExe.data(),static_cast<int>(explicitExe.size()),expectedUtf8.data(),
             utf8Bytes,nullptr,nullptr)==utf8Bytes,"UTF-8 SSH executable conversion failed");
        click(window,240);
        auto matchesSavedExe=[&]{
            try {
                std::ifstream in(desktopFile,std::ios::binary);
                if(!in)return false;
                auto value=Json::parse(in);
                return value["ssh"]["ssh_executable"]==expectedUtf8;
            }catch(const std::exception&){return false;}
        };
        try {
            waitFor(matchesSavedExe,"User-selected absolute OpenSSH exe path was not persisted");
        }catch(const std::exception&){
            // Report only sanitized state, not private usernames or paths.
            std::string actualType="unavailable";
            std::size_t actualSize=0;
            try {
                std::ifstream in(desktopFile,std::ios::binary);
                Json actual=Json::parse(in);
                actualType=actual["ssh"]["ssh_executable"].type_name();
                if(actual["ssh"]["ssh_executable"].is_string())
                    actualSize=actual["ssh"]["ssh_executable"].get<std::string>().size();
            }catch(const std::exception&){}
            const auto banner=windowText(GetDlgItem(window,280));
            const int bytes=WideCharToMultiByte(CP_UTF8,0,banner.data(),
                static_cast<int>(banner.size()),nullptr,0,nullptr,nullptr);
            std::string encoded(bytes>0?static_cast<std::size_t>(bytes):0,'\0');
            if(bytes>0)WideCharToMultiByte(CP_UTF8,0,banner.data(),
                static_cast<int>(banner.size()),encoded.data(),bytes,nullptr,nullptr);
            std::fprintf(stderr,
                "SSH backend save diagnosis: enabled=%d, observed_type=%s, actual_size=%zu, expected_size=%zu, banner=%s\n",
                IsWindowEnabled(GetDlgItem(window,240))?1:0,actualType.c_str(),
                actualSize,expectedUtf8.size(),encoded.c_str());
            throw;
        }
        edit(GetDlgItem(window,286),"");
        click(window,240);
        waitFor([&]{
            try {std::ifstream in(desktopFile);return in&&Json::parse(in)["ssh"]["ssh_executable"].is_null();}
            catch(const std::exception&){return false;}
        },"Reset-to-PATH OpenSSH backend was not persisted");
        SendMessageW(GetDlgItem(window,modeId),CB_SETCURSEL,0,0);SendMessageW(window,WM_COMMAND,MAKEWPARAM(modeId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,modeId)));
        click(window,203);need(IsWindowVisible(GetDlgItem(window,editorId)),"advanced page did not show full profile");
        unsigned short port=unusedPort(); auto profile=config(port);
        profile["proxies"]={{{"id","a"},{"kind","socks4a"},{"endpoint",{{"host","127.0.0.1"},{"port",1080}}},{"username",nullptr},{"password_env",nullptr}},{{"id","b"},{"kind","socks5"},{"endpoint",{{"host","127.0.0.1"},{"port",2080}}},{"username",nullptr},{"password_env",nullptr}}};
        edit(GetDlgItem(window,editorId),profile.dump()); click(window,applyId);
        waitFor([&]{ return windowText(GetDlgItem(window,statusId)).find(L"Остановлено |")!=std::wstring::npos; },"GUI Apply failed");
        need(SendMessageW(GetDlgItem(window,protocolId),CB_GETCURSEL,0,0)==2,"SOCKS4a display changed protocol");
        edit(GetDlgItem(window,hostId),"192.0.2.1");
        SendMessageW(GetDlgItem(window,proxyId),CB_SETCURSEL,1,0); SendMessageW(window,WM_COMMAND,MAKEWPARAM(proxyId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,proxyId)));
        auto text=windowText(GetDlgItem(window,editorId)); auto changed=Json::parse(std::string(text.begin(),text.end()));
        need(changed["proxies"][0]["endpoint"]["host"]=="192.0.2.1","quick edits lost on selection change"); need(changed["proxies"][0]["kind"]=="socks4a","SOCKS4a silently changed");
        click(window,200);click(window,startId); waitFor([&]{ return windowText(GetDlgItem(window,statusId)).find(L"Подключено |")!=std::wstring::npos; },"GUI Start failed");
        transfer(port); waitFor([&]{return ListView_GetItemCount(GetDlgItem(window,tableId))>0;},"GUI connection table empty");
        if(screenshot)captureWindow(window,std::filesystem::path(screenshot));
        click(window,stopId); waitFor([&]{ return windowText(GetDlgItem(window,statusId)).find(L"Остановлено |")!=std::wstring::npos; },"GUI Stop failed");
        SendMessageW(GetDlgItem(window,modeId),CB_SETCURSEL,1,0);SendMessageW(window,WM_COMMAND,MAKEWPARAM(modeId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,modeId)));
        edit(GetDlgItem(window,231),"server.example");edit(GetDlgItem(window,233),"testuser");edit(GetDlgItem(window,236),std::to_string(port));click(window,startId);
        need(windowText(GetDlgItem(window,280)).find(L"пересекается")!=std::wstring::npos,
             "managed SSH allowed ingress/primary-local-port collision");
        need(IsWindowEnabled(GetDlgItem(window,startId)),"collision rejection left start pending");
        // The second worker has its own port (base + 2); it too must be
        // excluded from the GUI's ingress listener before launching SSH.
        SendMessageW(GetDlgItem(window,288),CB_SETCURSEL,1,0);
        edit(GetDlgItem(window,236),std::to_string(port-2));click(window,startId);
        need(windowText(GetDlgItem(window,280)).find(L"пересекается")!=std::wstring::npos,
             "managed SSH pool allowed ingress/secondary-port recursion");
        SendMessageW(GetDlgItem(window,288),CB_SETCURSEL,0,0);
        edit(GetDlgItem(window,236),"1080");SendMessageW(GetDlgItem(window,modeId),CB_SETCURSEL,0,0);SendMessageW(window,WM_COMMAND,MAKEWPARAM(modeId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,modeId)));edit(GetDlgItem(window,editorId),changed.dump());
        click(window,202);need(IsWindow(GetDlgItem(window,282))&&IsWindow(GetDlgItem(window,283))&&IsWindow(GetDlgItem(window,284)),"Native capture GUI controls absent");
        waitFor([&]{return IsWindowEnabled(GetDlgItem(window,260));},"bounded application discovery did not finish");
        need(IsWindowVisible(GetDlgItem(window,261)),"application discovery table hidden");
        click(window,262);click(window,263);click(window,264);need(SendMessageW(GetDlgItem(window,267),BM_GETCHECK,0,0)==BST_UNCHECKED,"native template unexpectedly blocks other apps by default");
        click(window,200);
        SendMessageW(window,WM_CLOSE,0,0); need(WaitForSingleObject(process.hProcess,8000)==WAIT_OBJECT_0,"GUI close failed");
        DWORD exitCode=1; GetExitCodeProcess(process.hProcess,&exitCode); need(exitCode==0,"GUI nonzero exit");
        std::puts("PASS Win32 GUI: native pages, SSH editor, Apply, SOCKS4a, preserved edits, Start, real traffic, table, Stop, bounded discovery, presets, clean exit");
    } catch (...) { if(window) PostMessageW(window,WM_CLOSE,0,0); if(WaitForSingleObject(process.hProcess,3000)!=WAIT_OBJECT_0) TerminateProcess(process.hProcess,99); CloseHandle(process.hThread); CloseHandle(process.hProcess); throw; }
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
}
static void nativeOwnedPoolLifecycleTest() {
    uint64_t engine=0;
    std::vector<uint64_t> owned;
    try {
        Socket ingressSocket,primarySocket,secondarySocket;
        const auto ingress=listenOn(ingressSocket);
        const auto first=listenOn(primarySocket),second=listenOn(secondarySocket);
        auto profile=config(ingress);
        profile["proxies"]={{{"id","managed"},{"kind","socks5"},
            {"endpoint",{{"host","127.0.0.1"},{"port",first}}}}};
        profile["default_action"]={{"type","proxy"},{"id","managed"}};
        engine=result(fb_engine_create_json(profile.dump().c_str())).at("engine_id").get<uint64_t>();
        for(auto port:{first,second}) {
            const Json settings={{"host","qa.invalid"},{"user","qa"},{"local_port",port}};
            owned.push_back(result(fb_ssh_create_json(settings.dump().c_str())).at("ssh_id").get<uint64_t>());
        }
        // No SSH spawn: actual stopped supervisors must never appear ready.
        // Before this fix the GUI initialized a default 128-slot gate first;
        // its subsequent 64-slot pool failed with "different limits".
        for(bool enabled:{false,true,false,true}) {
            const auto request=ssh_pool_policy::ownedRequest(owned,enabled);
            result(fb_engine_sync_owned_ssh_pool_json(engine,request.dump().c_str()));
            const auto state=result(fb_engine_snapshot_json(engine));
            need(state["managed_pool"]["workers"].size()==2,"owned GUI pool not installed");
            need(state["managed_pool"]["ready_workers"]==0,"stopped SSH falsely marked ready");
            for(const auto& item:state["managed_pool"]["workers"])
                need(item["admission"]["limits"]["max_flows"]==64,"pause changed worker budget");
        }
        const Json clear={{"endpoint",nullptr},{"ready",false},{"grace_ms",0}};
        result(fb_engine_set_upstream_gate_json(engine,clear.dump().c_str()));
        const Json single={{"endpoint",{{"host","127.0.0.1"},{"port",first}}},
                           {"ready",false},{"grace_ms",30000}};
        result(fb_engine_set_upstream_gate_json(engine,single.dump().c_str()));
        need(result(fb_engine_snapshot_json(engine))["managed_upstream"]["limits"]["max_flows"]==128,
             "stopped pool budget not released before single-worker restart");
        result(fb_engine_set_upstream_gate_json(engine,clear.dump().c_str()));
        auto request=ssh_pool_policy::ownedRequest(owned,false);
        result(fb_engine_sync_owned_ssh_pool_json(engine,request.dump().c_str()));
        const auto stale=owned.back();fb_ssh_destroy(stale);owned.pop_back();
        char* rejected=fb_engine_sync_owned_ssh_pool_json(engine,request.dump().c_str());
        need(rejected!=nullptr,"stale response missing");
        auto failure=Json::parse(rejected);fb_string_free(rejected);
        need(!failure.value("ok",true),"destroyed supervisor accepted");
        fb_engine_destroy(engine);engine=0;
        for(auto id:owned)fb_ssh_destroy(id);owned.clear();
    } catch(...) {
        if(engine)fb_engine_destroy(engine);
        for(auto id:owned)fb_ssh_destroy(id);
        throw;
    }
    using ssh_pool_policy::captureAvailable;
    need(captureAvailable(true,true,false,true,false,false,false,false),
         "ready managed SSH prevents capture button from enabling");
    need(!captureAvailable(true,false,false,true,false,false,false,false),"managed capture without running engine");
    need(!captureAvailable(true,true,false,false,false,false,false,false),"managed capture without ready SSH");
    need(captureAvailable(false,false,false,false,false,false,false,false),"external capture unavailable when stopped");
    need(!captureAvailable(false,true,false,true,false,false,false,false),"external capture competes with engine");
    need(!captureAvailable(true,true,false,true,false,false,false,true),"capture enabled while helper is stopping");
    std::puts("PASS owned GUI pool: pause/resume limits, 2->1->2, stale IDs, managed capture button state");
}
int wmain(int argc,wchar_t** argv) {
    WSADATA data{}; if(WSAStartup(MAKEWORD(2,2),&data)) return 1;
    try { abiTest();nativeOwnedPoolLifecycleTest();nativeTemplateTest();nativeGuiListenerOwnerTest();nativeUnelevatedSshProfileTest();nativeLauncherArgumentTest(); if(argc>=2) guiTest(argv[1],argc>=3?argv[2]:nullptr); WSACleanup(); return 0; }
    catch(const std::exception& error) { std::fprintf(stderr,"FAIL: %s\n",error.what()); WSACleanup(); return 1; }
}
