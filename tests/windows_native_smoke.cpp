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
    std::puts("PASS native template export: basenames, deduplication, selected unknown hosts via proxy, other apps Direct, optional Block");
}
static void nativeLauncherArgumentTest() {
    wchar_t module[32768]{};DWORD count=GetModuleFileNameW(nullptr,module,32768);
    need(count&&count<32768,"test helper path unavailable");
    auto testApp=std::wstring(module,count);
    const auto event=L"Local\\FlowBridgeCaptureStop-{12345678-1234-1234-1234-123456789012}";
    auto params=capture_launcher::arguments(L"C:\\Users\\Test User\\profile.json",L"",{testApp},42,event);
    need(params.find(L"--gui-owner 42")!=std::wstring::npos,"GUI lifetime argument missing");
    need(params.find(L"--capture-app ")!=std::wstring::npos,"Selected process path missing");
    need(params.find(L"--stop-event ")!=std::wstring::npos,"Stop event argument missing");
    need(capture_launcher::quote(L"C:\\A B\\") == L"\"C:\\A B\\\\\"", "Windows backslash quoting incorrect");
    bool rejected=false;
    try {capture_launcher::arguments(L"relative.json",L"",{testApp},42,event);} catch(const std::exception&) {rejected=true;}
    need(rejected,"Relative elevated configuration accepted");
    rejected=false;
    try {capture_launcher::arguments(L"C:\\profile.json",L"",{L"relative.exe"},42,event);} catch(const std::exception&) {rejected=true;}
    need(rejected,"Relative capture executable accepted");
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
static void assertCompactLayout(HWND window) {
    need(SetWindowPos(window,nullptr,0,0,980,680,SWP_NOMOVE|SWP_NOZORDER)!=0,
         "Could not resize the GUI to compact Windows desktop");
    RECT client{};GetClientRect(window,&client);
    need(client.right>=920&&client.bottom>=600,"Compact window minimum client area not reached");
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
    inside(246); // Last managed-SSH timeout field
    need(sshHelp.bottom+6<=save.top,"Managed SSH form overlaps Save button");
    SendMessageW(mode,CB_SETCURSEL,0,0);
    SendMessageW(window,WM_COMMAND,MAKEWPARAM(230,CBN_SELCHANGE),reinterpret_cast<LPARAM>(mode));
    need(IsWindowVisible(GetDlgItem(window,2000))&&
         IsWindowVisible(GetDlgItem(window,2003))&&
         !IsWindowVisible(GetDlgItem(window,243)),
         "External proxy labels or managed-SSH help were shown in the wrong mode");
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
    click(window,203);
    inside(109);inside(111); // JSON editor and log
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
        assertCompactLayout(window);
        const int startId=100,stopId=101,applyId=102,proxyId=105,hostId=106,protocolId=108,editorId=109,tableId=110,statusId=112;
        const int modeId=230;SendMessageW(GetDlgItem(window,modeId),CB_SETCURSEL,0,0);SendMessageW(window,WM_COMMAND,MAKEWPARAM(modeId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,modeId)));
        need(IsWindow(GetDlgItem(window,231))&&IsWindow(GetDlgItem(window,234)),"structured SSH editor missing");
        click(window,201);need(IsWindowVisible(GetDlgItem(window,hostId)),"connection page did not show existing proxy controls");
        SendMessageW(GetDlgItem(window,modeId),CB_SETCURSEL,1,0);SendMessageW(window,WM_COMMAND,MAKEWPARAM(modeId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,modeId)));
        need(IsWindowVisible(GetDlgItem(window,231))&&!IsWindowVisible(GetDlgItem(window,hostId)),"managed SSH mode visibility failed");
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
        need(windowText(GetDlgItem(window,280)).find(L"должны отличаться")!=std::wstring::npos,"managed SSH allowed ingress/local-port collision");need(IsWindowEnabled(GetDlgItem(window,startId)),"collision rejection left start pending");
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
int wmain(int argc,wchar_t** argv) {
    WSADATA data{}; if(WSAStartup(MAKEWORD(2,2),&data)) return 1;
    try { abiTest();nativeTemplateTest();nativeLauncherArgumentTest(); if(argc>=2) guiTest(argv[1],argc>=3?argv[2]:nullptr); WSACleanup(); return 0; }
    catch(const std::exception& error) { std::fprintf(stderr,"FAIL: %s\n",error.what()); WSACleanup(); return 1; }
}
