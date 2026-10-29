from pathlib import Path

def edit(path,old,new,count=1):
    p=Path(path);s=p.read_text(encoding='utf-8')
    if s.count(old)!=count:raise RuntimeError(f'{path}: expected {count}, got {s.count(old)}: {old[:80]!r}')
    p.write_text(s.replace(old,new),encoding='utf-8')

p='native/windows/wfp/capture.h'
edit(p,'#include <vector>','#include <vector>\n#include "safety_filters.hpp"')
edit(p,'const std::vector<std::wstring>& bypass);','const std::vector<std::wstring>& bypass,\n               const std::vector<std::wstring>& quicApplications={}, bool remoteDns=false);')
edit(p,'    HANDLE engine_ = nullptr;','    HANDLE engine_ = nullptr;\n    SafetyFilters safety_;')
p='native/windows/wfp/capture.cpp'
edit(p,'void Capture::stop() noexcept {','void Capture::stop() noexcept {\n    safety_.stop();')
edit(p,'const std::vector<std::wstring>& bypass) {','const std::vector<std::wstring>& bypass, const std::vector<std::wstring>& quicApplications, bool remoteDns) {')
edit(p,'        check(FwpmTransactionCommit0(engine_),"Commit capture filters");','        check(FwpmTransactionCommit0(engine_),"Commit capture filters");\n        safety_.start(quicApplications,remoteDns);')
p='native/windows/wfp/service.cpp'
edit(p,'    if(ui.attached()&&nativeOptionsPath.empty())throw std::runtime_error("UI native options are required");','''    if(ui.attached()&&nativeOptionsPath.empty())throw std::runtime_error("UI native options are required");
    std::vector<std::wstring> quicApplications;
    if(nativeOptions.contains("quic_applications")) {
        auto paths=nativeOptions.at("quic_applications").get<std::vector<std::string>>();
        if(paths.size()>128)throw std::runtime_error("Too many selected QUIC applications");
        for(const auto& path:paths)quicApplications.push_back(native_ipc::wide(path));
        nativeOptions.erase("quic_applications");
    }''')
edit(p,'capture.start(p4,p6,bypassPaths);','capture.start(p4,p6,bypassPaths,quicApplications,nativeOptions.contains("dns")&&!nativeOptions["dns"].is_null());')
edit(p,'report["status"]["dns_active"]=dnsPolicy.active();','report["status"]["dns_active"]=dnsPolicy.active();\n                report["status"]["quic_guard_app_paths"]=quicApplications.size();')
edit('native/windows/wfp/CMakeLists.txt','service.cpp capture.cpp redirect_io.cpp)','service.cpp capture.cpp redirect_io.cpp safety_filters.cpp)')
p='native/windows/main.cpp'
edit(p,'        auto snapshot=response(fb_ssh_snapshot_json(ssh));','        nativeOptions["quic_applications"]=pendingOptions.at("selected_applications");\n        auto snapshot=response(fb_ssh_snapshot_json(ssh));')
edit(p,'ptMinTrackSize={1080,740}', 'ptMinTrackSize={1000,700}')
edit(p,'    HWND h=CreateWindowW(cls.lpszClassName,','''    RECT work{};SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);
    int initialWidth=std::min(1180,static_cast<int>(work.right-work.left));
    int initialHeight=std::min(740,static_cast<int>(work.bottom-work.top));
    HWND h=CreateWindowW(cls.lpszClassName,''')
edit(p,'CW_USEDEFAULT,CW_USEDEFAULT,1180,800,','work.left,work.top,initialWidth,initialHeight,')
edit(p,'Нативный захват в этом пакете недоступен. Выбор ниже сохраняется и экспортируется для отдельного нативного профиля; он не фильтрует клиентов локального SOCKS.','WFP: выберите приложения и включите перехват ниже. Нужен установленный драйвер. Локальный SOCKS этот выбор не применяет.')
edit(p,'Локальный SOCKS5 • приложения должны явно использовать этот прокси. Нативный захват недоступен.','Выберите локальный SOCKS или нативный перехват на странице приложений.')
edit(p,'В нативном профиле выбранные EXE идут через прокси; остальные — напрямую. Имена EXE не подтверждают издателя.','QUIC выбранных путей EXE блокируется; после обновления приложений повторите поиск.')
s=Path(p).read_text();a=s.index('void layout(){');b=s.index('LRESULT CALLBACK windowProc',a)
s=s[:a]+'''void layout(){
    RECT r{};GetClientRect(window,&r);int width=static_cast<int>(r.right),height=static_cast<int>(r.bottom),x=236,w=width-x-28;
    auto move=[](int id,int x,int y,int w,int h){MoveWindow(GetDlgItem(window,id),x,y,w,h,TRUE);};
    for(int id=NavDashboard;id<=NavAdvanced;++id)move(id,16,140+(id-NavDashboard)*54,180,44);
    move(Theme,16,height-62,180,40);move(ExportDiagnostics,16,height-110,180,40);
    move(Banner,x,108,w,19);move(PageTitle,x,30,w-330,36);move(PageSubtitle,x,78,w,25);
    move(Start,width-322,29,160,42);move(Stop,width-150,29,122,42);
    move(Badge,x+18,140,w-36,32);move(Status,x+18,181,w-36,28);move(Mode,x+18,221,w-36,28);
    move(Metrics,x+18,281,w-36,24);move(SshTitle,x+18,339,w-36,22);move(SshHealth,x+18,367,w-36,42);
    move(ConnectionsLabel,x,424,w,24);move(Connections,x,454,w,std::max(110,height-502));move(DashboardHelp,x,height-30,w,24);
    move(ConnectionSummary,x+18,146,210,24);move(ManagedMode,x+236,140,w-254,220);move(SshSummary,x+18,182,w-36,36);
    move(QuickLabel,x+18,254,140,22);move(Proxy,x+172,248,240,220);
    move(2000,x+18,299,300,22);move(2001,x+342,299,100,22);move(2002,x+466,299,200,22);
    move(Host,x+18,328,300,34);move(Port,x+342,328,100,34);move(Protocol,x+466,328,235,220);move(2003,x+18,389,w-36,48);
    int half=(w-60)/2;
    move(2010,x+16,228,half,20);move(2011,x+28+half,228,half,20);move(SshHost,x+16,250,half,28);move(SshUser,x+28+half,250,half,28);
    move(2012,x+16,287,half,20);move(2013,x+28+half,287,half,20);move(SshPort,x+16,309,half,28);move(LocalPort,x+28+half,309,half,28);
    move(2014,x+16,346,w-32,20);move(KeyPath,x+16,368,w-170,28);move(BrowseKey,x+w-138,368,122,28);
    move(2015,x+16,405,w-32,20);move(KnownHosts,x+16,427,w-170,28);move(BrowseKnown,x+w-138,427,122,28);
    move(Compression,x+16,465,w-32,24);
    int unit=(w-104)/4;int labels[]={2016,2017,2019,2020};int fields[]={Keepalive,KeepaliveCount,RetryInitial,RetryMax};
    for(int i=0;i<4;++i){move(labels[i],x+16+i*(unit+24),498,unit,20);move(fields[i],x+16+i*(unit+24),520,unit,28);}
    move(SshHelp,x+16,557,w-32,40);move(SaveDesktop,x,height-54,240,36);
    move(AppsHelp,x+16,136,w-32,44);move(PresetAI,x,192,140,34);move(PresetWeb,x+150,192,140,34);move(PresetBoth,x+300,192,140,34);move(Discover,x+w-190,192,190,34);
    move(ScanStatus,x,236,w,22);move(AppsSummary,x,264,w-170,22);move(BrowseApp,x+w-160,258,160,30);move(AppsTable,x,300,w,std::max(100,height-518));
    move(CaptureMode,x,height-208,w,24);move(RemoteDNS,x,height-178,w,24);move(DNSResolver,x,height-146,std::min(w,500),28);move(DNSHint,x,height-112,w,22);
    move(BlockOthers,x,height-80,w-300,24);move(ExportNative,x+w-290,height-76,290,34);move(2018,x,height-38,w,24);
    move(Apply,x,138,195,40);move(Open,x+207,138,180,40);move(Save,x+399,138,180,40);move(ConfigLabel,x,198,w,38);
    int editor=std::max(160,(height-340)*3/5);move(Config,x,246,w,editor);move(LogLabel,x,266+editor,w,24);move(Log,x,302+editor,w,std::max(70,height-editor-330));
}
'''+s[b:];Path(p).write_text(s)
edit(p,'if(activePage==0){panel(132,286);panel(304,370);panel(392,482);}','if(activePage==0){panel(132,258);panel(272,316);panel(332,416);}')
edit(p,'panel(132,232);bool managed=','panel(132,220);bool managed=')
edit(p,'panel(230,managed?634:470);','panel(224,managed?601:455);')
edit(p,'else if(activePage==2)panel(132,218);','else if(activePage==2)panel(132,182);')

p='native/windows/CMakeLists.txt';s=Path(p).read_text();s+='''
if(FLOWBRIDGE_BUILD_NATIVE_TESTS)
  add_executable(FlowBridgeSafetySmoke ../../tests/windows_safety_filters.cpp wfp/safety_filters.cpp)
  target_compile_definitions(FlowBridgeSafetySmoke PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
  target_include_directories(FlowBridgeSafetySmoke PRIVATE ../../third_party)
  target_link_libraries(FlowBridgeSafetySmoke PRIVATE fwpuclnt ws2_32 iphlpapi shell32 ole32 uuid user32 advapi32)
  if(MSVC)
    target_compile_options(FlowBridgeSafetySmoke PRIVATE /W4 /utf-8)
    set_property(TARGET FlowBridgeSafetySmoke PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  elseif(MINGW)
    target_link_options(FlowBridgeSafetySmoke PRIVATE -municode -static -static-libgcc -static-libstdc++)
  endif()
endif()
''';Path(p).write_text(s)

p='tests/windows_native_smoke.cpp'
edit(p,'    WSADATA data{}; if(WSAStartup(MAKEWORD(2,2),&data)) return 1;','    SetProcessDPIAware();\n    WSADATA data{}; if(WSAStartup(MAKEWORD(2,2),&data)) return 1;')
edit(p,'        const int startId=100,','        MoveWindow(window,0,0,1000,700,TRUE);\n        const int startId=100,')
edit(p,'        click(window,200);\n        SendMessageW(window,WM_CLOSE,0,0);','''        for(int page=0;page<4;++page){
            click(window,200+page);
            RECT bounds{};GetClientRect(window,&bounds);
            for(HWND child=GetWindow(window,GW_CHILD);child;child=GetWindow(child,GW_HWNDNEXT))if(IsWindowVisible(child)){
                RECT area{};GetWindowRect(child,&area);MapWindowPoints(nullptr,window,reinterpret_cast<POINT*>(&area),2);
                need(area.left>=0&&area.top>=0&&area.right<=bounds.right&&area.bottom<=bounds.bottom,"Visible control lies outside compact client bounds");
            }
            if(screenshot){auto path=std::filesystem::path(screenshot);path.replace_filename(path.stem().wstring()+L"-page-"+std::to_wstring(page)+L".bmp");captureWindow(window,path);}
        }
        click(window,201);SendMessageW(GetDlgItem(window,modeId),CB_SETCURSEL,1,0);SendMessageW(window,WM_COMMAND,MAKEWPARAM(modeId,CBN_SELCHANGE),reinterpret_cast<LPARAM>(GetDlgItem(window,modeId)));
        if(screenshot){auto path=std::filesystem::path(screenshot);path.replace_filename(path.stem().wstring()+L"-ssh.bmp");captureWindow(window,path);}
        click(window,200);
        SendMessageW(window,WM_CLOSE,0,0);''')

p='native/macos/Extension/TransparentProxyProvider.swift'
edit(p,'    private var limit = 128','    private var limit = 128\n    private var blockedQUIC = 0')
edit(p,'                var exclusions = [Self.rule("127.0.0.1", port: 0, prefix: 8), Self.rule("::1", port: 0, prefix: 128)]','''                settings.includedNetworkRules?.append(contentsOf:[
                    NENetworkRule(remoteNetwork:NWHostEndpoint(hostname:"0.0.0.0",port:"443"),remotePrefix:0,localNetwork:nil,localPrefix:0,protocol:.UDP,direction:.outbound),
                    NENetworkRule(remoteNetwork:NWHostEndpoint(hostname:"::",port:"443"),remotePrefix:0,localNetwork:nil,localPrefix:0,protocol:.UDP,direction:.outbound)])
                var exclusions = [Self.rule("127.0.0.1", port: 0, prefix: 8), Self.rule("::1", port: 0, prefix: 128),
                    NENetworkRule(remoteNetwork:NWHostEndpoint(hostname:"127.0.0.1",port:"0"),remotePrefix:8,localNetwork:nil,localPrefix:0,protocol:.UDP,direction:.outbound),
                    NENetworkRule(remoteNetwork:NWHostEndpoint(hostname:"::1",port:"0"),remotePrefix:128,localNetwork:nil,localPrefix:0,protocol:.UDP,direction:.outbound)]''')
edit(p,'    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool { false }','''    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        lock.lock();let source=profile;let isReady=ready;let bypass=bypassSigningIDs;lock.unlock()
        guard isReady else { reject(flow,"UDP guard is not ready");return true }
        guard let endpoint=remoteEndpoint as? NWHostEndpoint,let port=Int(endpoint.port) else {reject(flow,"Unknown UDP destination");return true}
        let identity=flow.metaData.sourceAppSigningIdentifier
        if bypass.contains(identity){return false}
        do {
            let request=try Bridge.text(["application":identity.isEmpty ? NSNull() : identity as Any,
                "destination":["host":endpoint.hostname,"port":port],"resolved_ip":NSNull()])
            let result=try source.withCString { c in try request.withCString { f in try Bridge.consume(fb_evaluate_json(c,f)) } }
            guard let decision=result["decision"] as? [String:Any],let action=decision["action"] as? [String:Any],let type=action["type"] as? String else {throw Bridge.error("UDP policy unavailable")}
            if type == "direct" {return false}
            lock.lock();blockedQUIC += 1;lock.unlock()
            reject(flow,"QUIC/UDP443 blocked by application proxy policy; use TCP");return true
        }catch {reject(flow,error.localizedDescription);return true}
    }''')
edit(p,'let isReady = ready; let currentSession = sessionID; let native = coreSession; lock.unlock()','let isReady = ready; let currentSession = sessionID; let native = coreSession; let udpBlocked=blockedQUIC; lock.unlock()')
edit(p,'"dns": SharedNativeSession.shared.snapshot(handle:native)]','"dns": SharedNativeSession.shared.snapshot(handle:native), "quic_blocked":udpBlocked]')
p='native/macos/App/FlowBridgeApp.swift'
edit(p,'UDP/QUIC и остальные порты пока не перехватываются.','QUIC проксируемых приложений блокируется; остальной UDP не перехватывается.')
print('Windows WFP guard, compact pages and macOS QUIC policy added')
