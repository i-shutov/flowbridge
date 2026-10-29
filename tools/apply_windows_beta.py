"""Exact source migration for the isolated Windows beta integration branch."""
from pathlib import Path

def edit(path, old, new, count=1):
    p=Path(path);s=p.read_text(encoding='utf-8')
    if s.count(old)!=count:raise RuntimeError(f'{path}: expected {count} matches, got {s.count(old)} for {old[:100]!r}')
    p.write_text(s.replace(old,new),encoding='utf-8')

I='native/windows/native_ipc.hpp'
edit(I,'        for(auto name:{L"profile.json",L"options.json"})std::filesystem::remove(directory_/name,error);','        if(!directory_.empty())for(auto name:{L"profile.json",L"options.json"})std::filesystem::remove(directory_/name,error);')
edit(I,'            for(unsigned i=0;i<32&&receive(pipe_,message);++i){last_=std::move(message);observed_=GetTickCount64();}','''            try { for(unsigned i=0;i<32&&receive(pipe_,message);++i){
                if(message.contains("state")){last_=std::move(message);observed_=GetTickCount64();}
            }} catch(...) {if(alive())throw;}''')

S='native/windows/wfp/service.cpp'
edit(S,'#include "capture.h"','#include "capture.h"\n#include "../native_ipc.hpp"\n#include "dns_policy.hpp"')
edit(S,'std::wstring profilePath, sshProfilePath;','''std::wstring profilePath, sshProfilePath, nativeOptionsPath, uiToken;
DWORD uiOwner=0;
native_ipc::Child ui;
std::deque<Json> recent;
void uiState(const std::string& state,Json snapshot=Json::object(),const std::string& error={}) {
    Json value={{"state",state},{"native",std::move(snapshot)}};if(!error.empty())value["error"]=error;
    ui.status(value);
}''')
edit(S,'        std::cerr<<line; OutputDebugStringA(line.c_str()); } catch (...) {}','''        std::cerr<<line; OutputDebugStringA(line.c_str());
        if(event.value("event",std::string())!="native_status") {
            recent.push_back({{"level",event.contains("error")?"error":"info"},{"message",event.dump()}});
            if(recent.size()>128)recent.pop_front();
        }
    } catch (...) {}''')
edit(S,'    Json nativeOptions=Json::object();','''    Json nativeOptions=nativeOptionsPath.empty()?Json::object():Json::parse(readConfiguration(nativeOptionsPath));
    if(!nativeOptionsPath.empty()&&!sshProfilePath.empty())throw std::runtime_error("Choose UI-owned or service-owned SSH, not both");
    if(ui.attached()&&nativeOptionsPath.empty())throw std::runtime_error("UI native options are required");
    uiState("starting");''')
edit(S,'    Capture capture;','''    Capture capture; DnsPolicy dnsPolicy;
    auto heartbeat=[&]{
        if(!ui.alive()){stopping=true;return;}
        Json message;
        try {
            for(unsigned i=0;i<16&&ui.read(message);++i){
                if(message.value("stop",false)){stopping=true;return;}
                if(message.contains("ready")&&message["ready"].is_boolean()) {
                    auto gate=Json{{"ready",message["ready"]}}.dump();
                    response(fb_native_set_gate_json(native.id,gate.c_str()));
                }
            }
        } catch(...) {stopping=true;}
    };''')
edit(S,'        if(!stopping) capture.start(p4,p6,bypassPaths);','''        heartbeat();
        if(!stopping) capture.start(p4,p6,bypassPaths);
        if(!stopping && nativeOptions.contains("dns") && !nativeOptions["dns"].is_null()) {
            response(fb_native_dns_start_json(native.id,R"({"listen":"127.0.0.1:53"})"));
            dnsPolicy.enter();
        }
        heartbeat();''')
edit(S,'        while(!stopping) {\n            if(ssh.id)', '        while(!stopping) {\n            heartbeat(); if(stopping)break;\n            if(ssh.id)')
edit(S,'                report["event"]="native_status";log(report);lastSnapshot=GetTickCount64();','''                report["status"]["dns_active"]=dnsPolicy.active();
                report["status"]["dns_scope"]=dnsPolicy.active()?"system_standard_dns":"unchanged";
                {std::lock_guard<std::mutex> guard(logLock);report["events"]=recent;}
                uiState("ready",report);lastSnapshot=GetTickCount64();''')
edit(S,'        capture.stop(); fb_native_destroy(native.id); finish(); native.id=0;','''        capture.stop();
        dnsPolicy.restore();
        fb_native_destroy(native.id); finish(); native.id=0;
        uiState("stopped",{{"ok",true},{"status",{{"running",false},{"transparent",true}}}});''')
edit(S,'    } catch(...) {stopping=true; capture.stop(); fb_native_destroy(native.id); finish(); native.id=0; throw;}','''    } catch(...) {
        stopping=true;capture.stop();
        try{dnsPolicy.restore();}catch(const std::exception& error){log({{"event","dns_restore_failed"},{"error",error.what()}});}
        fb_native_destroy(native.id);finish();native.id=0;throw;
    }''')
edit(S,'            else if(arg==L"--ssh-profile" && i+1<argc) sshProfilePath=argv[++i];','''            else if(arg==L"--ssh-profile" && i+1<argc) sshProfilePath=argv[++i];
            else if(arg==L"--native-options" && i+1<argc) nativeOptionsPath=argv[++i];
            else if(arg==L"--ui-token" && i+1<argc) uiToken=argv[++i];
            else if(arg==L"--owner" && i+1<argc) {
                std::wstring number=argv[++i];size_t used=0;auto parsed=std::stoul(number,&used);
                if(used!=number.size()||!parsed)throw std::runtime_error("Invalid UI owner PID");uiOwner=parsed;
            }''')
edit(S,'        bypassPaths.emplace_back(self,length);','''        bypassPaths.emplace_back(self,length);
        if(!nativeOptionsPath.empty()&&!std::filesystem::path(nativeOptionsPath).is_absolute())throw std::runtime_error("Native options path must be absolute");
        if(!uiToken.empty()){if(!console||!uiOwner)throw std::runtime_error("Invalid UI invocation");ui.attach(uiToken,uiOwner);}
        else if(uiOwner)throw std::runtime_error("UI token required");''')
edit(S,'} catch(const std::exception& e) {log({{"event","faulted"},{"error",e.what()}});return 1;}','} catch(const std::exception& e) {uiState("faulted",Json::object(),e.what());log({{"event","faulted"},{"error",e.what()}});return 1;}')
edit('native/windows/wfp/CMakeLists.txt','Threads::Threads fwpuclnt ws2_32 advapi32 userenv bcrypt ntdll','Threads::Threads fwpuclnt ws2_32 advapi32 userenv bcrypt ntdll shell32 ole32 uuid')

W='native/windows/main.cpp'
edit(W,'#include <windows.h>','#include <winsock2.h>\n#include <ws2tcpip.h>\n#include <windows.h>')
edit(W,'#include "native_profile.hpp"','#include "native_profile.hpp"\n#include "native_ipc.hpp"')
edit(W,'ExportDiagnostics=281 };','ExportDiagnostics=281, CaptureMode=282, RemoteDNS=283, DNSResolver=284, DNSHint=285 };')
edit(W,'{"dark",dark}};','''{"dark",dark},{"native_capture",SendMessageW(GetDlgItem(window,CaptureMode),BM_GETCHECK,0,0)==BST_CHECKED},
        {"remote_dns",SendMessageW(GetDlgItem(window,RemoteDNS),BM_GETCHECK,0,0)==BST_CHECKED},
        {"dns_resolver",utf8(GetDlgItem(window,DNSResolver))}};''')
edit(W,'    void gate(bool ready){','''    native_ipc::Parent capture;
    bool nativeWanted=false;Json pendingOptions;
    void launchNative() {
        auto root=Json::parse(pending);
        root=native_profile::build(std::move(root),pendingOptions.at("selected_applications").get<std::vector<std::string>>(),
            "managed-ssh",pendingOptions.value("block_other_applications",false));
        Json nativeOptions={{"managed_endpoint",{{"host","127.0.0.1"},{"port",activeSsh.at("local_port")}}},
            {"ready",false},{"ready_lease_ms",5000},{"pause_grace_ms",30000}};
        auto literal=[](const std::string& value){IN_ADDR v4{};IN6_ADDR v6{};return InetPtonA(AF_INET,value.c_str(),&v4)==1||InetPtonA(AF_INET6,value.c_str(),&v6)==1;};
        if(pendingOptions.value("remote_dns",true)) {
            if(!literal(activeSsh.at("host").get<std::string>()))throw std::runtime_error("Для удалённого DNS этой беты укажите IP SSH-сервера, а не hostname.");
            auto resolver=pendingOptions.value("dns_resolver",std::string());
            if(resolver.empty())resolver=response(fb_ssh_remote_dns_json(ssh)).at("servers").at(0).get<std::string>();
            if(!literal(resolver))throw std::runtime_error("DNS-сервер должен быть IP-адресом удалённой машины.");
            nativeOptions["dns"]={{"resolver",{{"host",resolver},{"port",53}}},{"timeout_ms",5000}};
        }
        auto snapshot=response(fb_ssh_snapshot_json(ssh));
        auto path=snapshot.at("status").at("backend_path").get<std::string>();
        capture.start(root,nativeOptions,path);
    }
    void gate(bool ready){''')
edit(W,'if(action==-1) {waiting=false;','if(action==-1) {capture.stop();waiting=false;')
edit(W,'                    else if(action==Start||action==Apply) {','''                    else if(action==Start||action==Apply) {
                        if(capture.exists())throw std::runtime_error("Сначала остановите нативный перехват перед изменением настроек.");
                        if(action==Start){
                            nativeWanted=options.value("native_capture",false);pendingOptions=options;
                            if(nativeWanted&&!options.value("managed_ssh",false))throw std::runtime_error("Нативная бета требует встроенного SSH.");
                            if(nativeWanted&&options.at("selected_applications").empty())throw std::runtime_error("Выберите приложения для перехвата.");
                        }''')
edit(W,'                    } else if(action==Stop) {waiting=false;','                    } else if(action==Stop) {capture.stop();nativeWanted=false;waiting=false;')
edit(W,'                        if(waiting&&state=="ready") {response(fb_engine_start_json(engine));waiting=false;result->saved=pending;}','''                        if(waiting&&state=="ready") {
                            if(nativeWanted){if(!capture.exists())launchNative();}
                            else {response(fb_engine_start_json(engine));waiting=false;result->saved=pending;}
                        }''')
edit(W,'                    if(engine)result->snapshot=response(fb_engine_snapshot_json(engine));','''                    if(capture.exists()) {
                        auto observed=capture.poll(result->ssh.is_object()&&result->ssh.at("status").value("state",std::string())=="ready");
                        auto state=observed.value("state",std::string("starting"));
                        result->snapshot=observed.value("native",Json{{"status",{{"running",false},{"transparent",true}}}});
                        if(!result->snapshot.contains("status"))result->snapshot={{"status",{{"running",false},{"transparent",true}}}};
                        if(state=="ready"&&waiting){waiting=false;result->saved=pending;result->acceptedDesktop=pendingOptions;}
                        if(observed.contains("error"))throw std::runtime_error(observed["error"].get<std::string>());
                        if(observed.contains("warning"))result->error=observed["warning"].get<std::string>();
                    }else if(engine)result->snapshot=response(fb_engine_snapshot_json(engine));''')
edit(W,'                result->error=e.what();result->saved.clear();','''                result->error=e.what();result->saved.clear();
                if(action==-1)result->exit=false;
                if(capture.exists()&&!capture.alive()){try{capture.stop();}catch(...){}waiting=false;nativeWanted=false;}
                if(capture.exists()&&(waiting||action==Start)){try{capture.stop();}catch(...){}waiting=false;}
''')
edit(W,'for(int id:{Start,Stop,Apply,Open,Save,Proxy,Host,Port,Protocol,Config,Discover,ExportNative,','for(int id:{CaptureMode,RemoteDNS,DNSResolver,Start,Stop,Apply,Open,Save,Proxy,Host,Port,Protocol,Config,Discover,ExportNative,')
edit(W,'    setText(GetDlgItem(window,Badge),running?"●  Локальный SOCKS5 работает":"●  Не подключено");','''    bool native=status.value("transparent",false);
    setText(GetDlgItem(window,Badge),running?(native?"●  Нативный TCP-перехват работает":"●  Локальный SOCKS5 работает"):"●  Не подключено");
    setText(GetDlgItem(window,Mode),native?(status.value("dns_active",false)?"TCP + системный DNS через SSH. Собственный DoH/DoT не перехватывается.":"Нативный TCP. Системный DNS не перенаправлен."):"Локальный SOCKS5: приложения должны явно использовать прокси.");''')
edit(W,'        label(L"Существующие TCP-соединения не восстанавливаются после обрыва SSH.",DashboardHelp,0);','''        label(L"Существующие TCP-соединения не восстанавливаются после обрыва SSH.",DashboardHelp,0);
        add(L"BUTTON",L"Перехватывать выбранные приложения через WFP",BS_AUTOCHECKBOX|WS_TABSTOP,CaptureMode,2);
        add(L"BUTTON",L"Разрешать DNS на удалённом SSH-сервере",BS_AUTOCHECKBOX|WS_TABSTOP,RemoteDNS,2);
        add(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,DNSResolver,2);
        SendMessageW(GetDlgItem(h,DNSResolver),EM_SETCUEBANNER,0,reinterpret_cast<LPARAM>(L"Удалённый DNS IP · пусто = автоматически"));
        label(L"DNS применяется ко всей системе; существующая NRPT-политика не заменяется.",DNSHint,2);''')
edit(W,'        SendMessageW(mode,CB_SETCURSEL,desktop.value("managed_ssh",false)?1:0,0);','''        SendMessageW(GetDlgItem(h,CaptureMode),BM_SETCHECK,desktop.value("native_capture",false)?BST_CHECKED:BST_UNCHECKED,0);
        SendMessageW(GetDlgItem(h,RemoteDNS),BM_SETCHECK,desktop.value("remote_dns",true)?BST_CHECKED:BST_UNCHECKED,0);
        setText(GetDlgItem(h,DNSResolver),desktop.value("dns_resolver",std::string()));
        SendMessageW(mode,CB_SETCURSEL,desktop.value("managed_ssh",false)?1:0,0);''')
edit(W,'if(id==Start||id==Apply||id==SaveDesktop){workerError.clear();','if(id==Start||id==Apply||id==SaveDesktop){captureSelections();workerError.clear();')
edit(W,'        if(result->exit) { DestroyWindow(h); return 0; }','''        if(closing&&!result->error.empty()) {closing=false;SetTimer(h,1,1000,nullptr);note("Остановка не подтверждена: "+result->error);enableControls();return 0;}
        if(result->exit) { DestroyWindow(h); return 0; }''')
edit(W,'    move(AppsHelp,x+24,150,w-48,58);','''    move(AppsHelp,x+24,150,w-48,58);''')
# A compact, two-column applications page with real activation, not export-only.
edit(W,'    move(Apply,x,138,195,40);','''    move(AppsHelp,x+16,136,w-32,44);
    move(PresetAI,x,192,140,34);move(PresetWeb,x+150,192,140,34);move(PresetBoth,x+300,192,140,34);move(Discover,x+w-190,192,190,34);
    move(ScanStatus,x,236,w,22);move(AppsSummary,x,264,w-170,22);move(BrowseApp,x+w-160,258,160,30);
    move(AppsTable,x,300,w,std::max(100,height-518));
    move(CaptureMode,x,height-208,w,24);move(RemoteDNS,x,height-178,w,24);
    move(DNSResolver,x,height-146,std::min(w,500),28);move(DNSHint,x,height-112,w,22);
    move(BlockOthers,x,height-80,w-300,24);move(ExportNative,x+w-290,height-76,290,34);move(2018,x,height-38,w,24);
    move(Apply,x,138,195,40);''')
edit(W,'case WM_GETMINMAXINFO: reinterpret_cast<MINMAXINFO*>(l)->ptMinTrackSize={1200,940};','case WM_GETMINMAXINFO: reinterpret_cast<MINMAXINFO*>(l)->ptMinTrackSize={1080,740};')
edit(W,'CW_USEDEFAULT,CW_USEDEFAULT,1280,1000,','CW_USEDEFAULT,CW_USEDEFAULT,1180,800,')
# Keep the dense connection page fully usable at 740-pixel window height.
edit(W,'    move(Apply,x,138,195,40);','''    move(2010,x+16,238,half,20);move(2011,x+40+half,238,half,20);move(SshHost,x+16,261,half,28);move(SshUser,x+40+half,261,half,28);
    move(2012,x+16,300,half,20);move(2013,x+40+half,300,half,20);move(SshPort,x+16,323,half,28);move(LocalPort,x+40+half,323,half,28);
    move(2014,x+16,362,w-32,20);move(KeyPath,x+16,385,w-170,28);move(BrowseKey,x+w-138,385,122,28);
    move(2015,x+16,423,w-32,20);move(KnownHosts,x+16,446,w-170,28);move(BrowseKnown,x+w-138,446,122,28);
    move(Compression,x+16,486,w-32,24);
    for(int i=0;i<4;++i){move(labels[i],x+16+i*(unit+24),520,unit,20);move(fields[i],x+16+i*(unit+24),543,unit,28);}
    move(SshHelp,x+16,584,w-32,42);
    move(Apply,x,138,195,40);''')
edit(W,'panel(246,managed?782:470);','panel(230,managed?634:470);')
edit(W,'В этом пакете захват недоступен; локальный SOCKS не фильтрует приложения.','Для запуска включите WFP на странице приложений; локальный SOCKS сам не фильтрует приложения.')
print('Windows GUI, owned IPC, native helper and transactional DNS are wired')
