#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <stdexcept>
#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <vector>
#include "discovery.hpp"
#include "native_profile.hpp"
#include "proxifyre_export.hpp"
#include "capture_launcher.hpp"
#include "ssh_pool_policy.hpp"
#include "rule_editor_win32.hpp"
#include "flowbridge.h"
#include "nlohmann/json.hpp"

using Json = nlohmann::json;
namespace {
constexpr size_t MaxBytes = 1024 * 1024;
constexpr UINT Completed = WM_APP + 1;
enum { Start=100, Stop, Apply, Open, Save, Proxy, Host, Port, Protocol, Config, Connections, Log, Status, Mode, QuickLabel, ConfigLabel, ConnectionsLabel, LogLabel, NavDashboard=200, NavConnection, NavApps, NavAdvanced, Theme=204, PageTitle=205, PageSubtitle=206, Badge=207, Metrics=208, DashboardHelp=209, SshHealth=210, ManagedMode=230, SshHost=231, SshPort=232, SshUser=233, KeyPath=234, KnownHosts=235, LocalPort=236, Compression=237, Keepalive=238, KeepaliveCount=239, SaveDesktop=240, BrowseKey=241, BrowseKnown=242, SshHelp=243, ConnectionSummary=244, Discover=260, AppsTable=261, PresetAI=262, PresetWeb=263, PresetBoth=264, BrowseApp=265, ExportNative=266, BlockOthers=267, AppsHelp=268, AppsSummary=269, ScanStatus=270, SshTitle=271, SshSummary=272, RetryInitial=245, RetryMax=246, Banner=280, ExportDiagnostics=281, StartCapture=282, StopCapture=283, CaptureStatus=284, RemoteDns=285, SshExecutable=286, BrowseSsh=287, SshPoolWorkers=288, VisualRules=289, SshPoolLabel=2030 };
constexpr int DiscoverCommand=900, PollCommand=999;
std::map<int,int> pages; // -1 global; 0 dashboard; 1 connection; 2 applications; 3 advanced
int activePage=0;
HFONT bodyFont{},titleFont{},headingFont{},smallFont{};
HBRUSH backgroundBrush{},cardBrush{},sidebarBrush{};
bool dark=false,engineRunning=false,loadingApps=false,discoveryDone=false,pendingStart=false,tunnelReady=true;
std::filesystem::path desktopPath;
Json catalog=Json::object(),desktop=Json::object();
std::vector<discovery::App> discovered;
std::set<std::string> selectedApps;
std::string selectedPreset="ai_web";
COLORREF bg(),card(),ink(),muted();
void switchPage(int page); void layout(); void refreshApps(); void saveDesktop(); Json desktopSettings();
HWND window{}, configEdit{}, table{}, logEdit{};
std::filesystem::path profile;
bool busy=false, closing=false, filling=false, quickDirty=false;
bool shutdownDispatched=false;
std::string localLog, workerError;
std::string selectedProxyId;
Json draft;
Json latestEngineSnapshot=Json::object(),latestSshSnapshot=Json::object();
capture_launcher::Session nativeCapture;

const char* initialConfig = R"({"version":1,"listen":"127.0.0.1:1081","proxies":[{"id":"ssh","kind":"socks5","endpoint":{"host":"127.0.0.1","port":1080},"username":null,"password_env":null}],"chains":[],"rules":[],"default_action":{"type":"proxy","id":"ssh"},"connect_timeout_ms":10000,"handshake_timeout_ms":10000,"idle_timeout_ms":300000,"max_connections":512})";
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if (!n) throw std::runtime_error("Invalid UTF-8 text.");
    std::wstring out(n,0); MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n); return out;
}
std::string utf8(HWND h) {
    int n=GetWindowTextLengthW(h); std::wstring s(n+1,0); GetWindowTextW(h,s.data(),n+1); s.resize(n);
    if (!n) return {};
    int count=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),n,nullptr,0,nullptr,nullptr);
    if (!count) throw std::runtime_error("Invalid Unicode text.");
    std::string out(count,0); WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),n,out.data(),count,nullptr,nullptr); return out;
}
void setText(HWND h,const std::string& s) {
    std::string normalized; normalized.reserve(s.size());
    for(size_t i=0;i<s.size();++i) { if(s[i]=='\n' && (i==0 || s[i-1]!='\r')) normalized+='\r'; normalized+=s[i]; }
    auto value=wide(normalized); SetWindowTextW(h,value.c_str());
}
Json response(char* value) {
    if (!value) throw std::runtime_error("Engine returned no response.");
    std::unique_ptr<char,decltype(&fb_string_free)> owned(value,fb_string_free);
    auto j=Json::parse(value);
    if (!j.value("ok",false)) throw std::runtime_error(j.value("error",std::string("Engine operation failed.")));
    return j;
}
std::string readFile(const std::filesystem::path& path) {
    if (std::filesystem::file_size(path)>MaxBytes) throw std::runtime_error("Profile exceeds the 1 MiB editor limit.");
    std::ifstream in(path,std::ios::binary); if (!in) throw std::runtime_error("Could not open profile.");
    std::string value((std::istreambuf_iterator<char>(in)),{});
    if (in.bad() || value.size()>MaxBytes || value.find('\0')!=std::string::npos) throw std::runtime_error("Could not read profile or profile contains a NUL byte.");
    wide(value); return value;
}
void writeFile(const std::filesystem::path& path,const std::string& value) {
    auto dir=path.parent_path(); std::filesystem::create_directories(dir);
    wchar_t temp[MAX_PATH]{};
    if (!GetTempFileNameW(dir.c_str(),L"fbr",0,temp)) throw std::runtime_error("Could not create profile staging file.");
    try {
        std::ofstream out(std::filesystem::path(temp),std::ios::binary); out.write(value.data(),static_cast<std::streamsize>(value.size())); out.close();
        if (!out || !MoveFileExW(temp,path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) throw std::runtime_error("Could not save profile; previous file was preserved.");
    } catch (...) { DeleteFileW(temp); throw; }
}
void note(const std::string& message) {
    localLog += message+"\r\n"; if (localLog.size()>24000) localLog.erase(0,localLog.size()-24000);
    setText(GetDlgItem(window,Status),message);
    if(GetDlgItem(window,Banner))setText(GetDlgItem(window,Banner),message);
    if(logEdit) setText(logEdit,localLog);
}
void fillQuick() {
    filling=true; HWND combo=GetDlgItem(window,Proxy); auto selected=utf8(combo); SendMessageW(combo,CB_RESETCONTENT,0,0);
    try {
        draft=Json::parse(utf8(configEdit));
        for (auto& p:draft.at("proxies")) { auto id=wide(p.at("id").get<std::string>()); SendMessageW(combo,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(id.c_str())); }
        int index=0;
        for(size_t i=0;i<draft.at("proxies").size();++i) if(draft["proxies"][i].value("id",std::string())==selected) index=static_cast<int>(i);
        SendMessageW(combo,CB_SETCURSEL,index,0);
        if (!draft.at("proxies").empty()) {
            auto& p=draft["proxies"][index]; setText(GetDlgItem(window,Host),p["endpoint"]["host"].get<std::string>()); setText(GetDlgItem(window,Port),std::to_string(p["endpoint"]["port"].get<int>()));
            selectedProxyId=p.at("id").get<std::string>();
            SendMessageW(GetDlgItem(window,Protocol),CB_SETCURSEL,p["kind"]=="http_connect"?1:(p["kind"]=="socks4a"?2:0),0);
        } else { selectedProxyId.clear(); SetWindowTextW(GetDlgItem(window,Host),L""); SetWindowTextW(GetDlgItem(window,Port),L""); }
    } catch (...) { SendMessageW(combo,CB_RESETCONTENT,0,0); }
    filling=false; quickDirty=false;
}
std::string configuration() {
    auto text=utf8(configEdit); if(text.size()>MaxBytes) throw std::runtime_error("Profile exceeds the 1 MiB editor limit."); auto j=Json::parse(text);
    if(quickDirty) {
        auto selected=selectedProxyId;
        auto found=std::find_if(j.at("proxies").begin(),j.at("proxies").end(),[&](const Json& p){return p.value("id",std::string())==selected;});
        if(found==j.at("proxies").end()) throw std::runtime_error("Selected proxy was removed or renamed in JSON. Apply the JSON first, then edit the proxy.");
        auto host=utf8(GetDlgItem(window,Host)), port=utf8(GetDlgItem(window,Port));
        size_t consumed=0; unsigned long number=std::stoul(port,&consumed);
        if(host.empty() || consumed!=port.size() || number<1 || number>65535) throw std::runtime_error("Proxy host is required; port must be 1–65535.");
        (*found)["endpoint"]={{"host",host},{"port",number}};
        auto protocol=SendMessageW(GetDlgItem(window,Protocol),CB_GETCURSEL,0,0);
        if(protocol<0 || protocol>2) throw std::runtime_error("Select an upstream proxy protocol.");
        (*found)["kind"]=protocol==1?"http_connect":(protocol==2?"socks4a":"socks5");
        text=j.dump(2); if(text.size()>MaxBytes) throw std::runtime_error("Formatted profile exceeds the 1 MiB editor limit."); setText(configEdit,text); quickDirty=false;
    }
    return text;
}
void selectedProxy() {
    auto selected=utf8(GetDlgItem(window,Proxy));
    filling=true;
    try {
        // Flush the previous entry before replacing its quick editor fields.
        auto current=Json::parse(configuration());
        auto found=std::find_if(current.at("proxies").begin(),current.at("proxies").end(),[&](const Json& p){return p.value("id",std::string())==selected;});
        if(found==current.at("proxies").end()) throw std::runtime_error("Selected proxy was removed or renamed in JSON. Apply the JSON first.");
        auto& p=*found;
        auto host=p.at("endpoint").at("host").get<std::string>();
        auto port=std::to_string(p.at("endpoint").at("port").get<int>());
        auto kind=p.at("kind").get<std::string>();
        setText(GetDlgItem(window,Host),host); setText(GetDlgItem(window,Port),port);
        SendMessageW(GetDlgItem(window,Protocol),CB_SETCURSEL,kind=="http_connect"?1:(kind=="socks4a"?2:0),0);
        selectedProxyId=selected; quickDirty=false;
    } catch (const std::exception& e) {
        auto previous=wide(selectedProxyId);
        auto index=SendMessageW(GetDlgItem(window,Proxy),CB_FINDSTRINGEXACT,static_cast<WPARAM>(-1),reinterpret_cast<LPARAM>(previous.c_str()));
        SendMessageW(GetDlgItem(window,Proxy),CB_SETCURSEL,index,0);
        note(e.what());
    }
    filling=false;
}
int integerField(int id,int minimum,int maximum) {
    auto value=utf8(GetDlgItem(window,id)); size_t n=0; long result=std::stol(value,&n);
    if(n!=value.size()||result<minimum||result>maximum) throw std::runtime_error("Числовое поле вне допустимого диапазона.");
    return static_cast<int>(result);
}
Json sshSettings() {
    auto optional=[](int id)->Json {auto value=utf8(GetDlgItem(window,id)); return value.empty()?Json(nullptr):Json(value);};
    return {{"host",utf8(GetDlgItem(window,SshHost))},{"port",integerField(SshPort,1,65535)},{"user",utf8(GetDlgItem(window,SshUser))},{"identity_file",optional(KeyPath)},{"known_hosts_file",optional(KnownHosts)},{"ssh_executable",optional(SshExecutable)},{"local_port",integerField(LocalPort,1,65535)},{"compression",SendMessageW(GetDlgItem(window,Compression),BM_GETCHECK,0,0)==BST_CHECKED},{"server_alive_interval_secs",integerField(Keepalive,1,3600)},{"server_alive_count_max",integerField(KeepaliveCount,1,100)},{"restart_initial_delay_ms",integerField(RetryInitial,100,60000)},{"restart_max_delay_ms",integerField(RetryMax,100,300000)}};
}
Json desktopSettings() {
    Json selected=Json::array();for(const auto& path:selectedApps)selected.push_back(path);
    return {{"version",1},{"managed_ssh",SendMessageW(GetDlgItem(window,ManagedMode),CB_GETCURSEL,0,0)==1},{"ssh_workers",static_cast<int>(SendMessageW(GetDlgItem(window,SshPoolWorkers),CB_GETCURSEL,0,0))+1},{"ssh",sshSettings()},{"preset",selectedPreset},{"selected_applications",selected},{"block_other_applications",SendMessageW(GetDlgItem(window,BlockOthers),BM_GETCHECK,0,0)==BST_CHECKED},{"remote_dns_via_ssh",SendMessageW(GetDlgItem(window,RemoteDns),BM_GETCHECK,0,0)==BST_CHECKED},{"dark",dark}};
}
void validateDesktop(const Json& value) {
    const auto& ssh=value.at("ssh");auto host=ssh.at("host").get<std::string>(),user=ssh.at("user").get<std::string>();
    auto allowed=[](const std::string& text,const std::string& punctuation){return std::all_of(text.begin(),text.end(),[&](unsigned char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||punctuation.find(static_cast<char>(c))!=std::string::npos;});};
    bool managed=value.value("managed_ssh",false);
    const int workerCount=value.value("ssh_workers",1);
    const int basePort=ssh.at("local_port").get<int>();
    if(workerCount<1||workerCount>4||basePort+2*(workerCount-1)>65535)
        throw std::runtime_error("Пул SSH: от 1 до 4 процессов; диапазон локальных SOCKS-портов переполнен.");
    if(value.contains("remote_dns_via_ssh")&&!value["remote_dns_via_ssh"].is_boolean())
        throw std::runtime_error("Режим удалённого DNS должен быть логическим значением.");
    if((managed||!host.empty())&&(host.empty()||host.size()>253||host[0]=='-'||!allowed(host,".-:_[]%")))throw std::runtime_error("SSH-сервер: укажите hostname / IP без пробелов, URI и параметров командной строки.");
    if((managed||!user.empty())&&(user.empty()||user.size()>128||user[0]=='-'||!allowed(user,"._-")))throw std::runtime_error("SSH-пользователь: нужны ASCII буквы, цифры, точка, дефис или подчёркивание.");
    for(const auto* key:{"identity_file","known_hosts_file","ssh_executable"})if(!ssh.at(key).is_null()){auto path=ssh.at(key).get<std::string>();if(path.empty()||path.size()>4096||std::any_of(path.begin(),path.end(),[](unsigned char c){return c<32||c==127||c=='"';}))throw std::runtime_error("Путь ключа / known_hosts содержит недопустимые символы.");}
    if(!ssh.at("ssh_executable").is_null()){
        const auto raw=ssh.at("ssh_executable").get<std::string>();
        const auto value=std::filesystem::path(wide(raw));
        const auto path=value.wstring();
        if(!value.is_absolute()||path.rfind(L"\\\\",0)==0||
           _wcsicmp(value.extension().c_str(),L".exe")!=0)
            throw std::runtime_error("Выбранный SSH-клиент должен быть локальным абсолютным путём к .exe, например C:\\\\Windows\\\\System32\\\\OpenSSH\\\\ssh.exe.");
    }
    if(ssh.at("restart_max_delay_ms").get<int>()<ssh.at("restart_initial_delay_ms").get<int>())throw std::runtime_error("Максимальная пауза повтора не может быть меньше начальной.");
}
void saveDesktop() { if(desktopPath.empty())throw std::runtime_error("Недоступна папка настроек пользователя.");auto value=desktopSettings();validateDesktop(value);writeFile(desktopPath,value.dump(2));desktop=std::move(value); }
std::string commandConfiguration() {
    auto value=Json::parse(configuration());
    if(SendMessageW(GetDlgItem(window,ManagedMode),CB_GETCURSEL,0,0)==1) {
        auto settings=sshSettings();
        Json managed={{"id","managed-ssh"},{"kind","socks5"},{"endpoint",{{"host","127.0.0.1"},{"port",settings["local_port"]}}},{"username",nullptr},{"password_env",nullptr}};
        auto& proxies=value["proxies"];auto found=std::find_if(proxies.begin(),proxies.end(),[](const Json& p){return p.value("id",std::string())=="managed-ssh";});
        if(found==proxies.end())proxies.push_back(managed);else *found=managed;
        value["default_action"]={{"type","proxy"},{"id","managed-ssh"}};
        value["remote_dns_via_ssh"] = SendMessageW(GetDlgItem(window,RemoteDns),BM_GETCHECK,0,0)==BST_CHECKED;
        setText(configEdit,value.dump(2));fillQuick();
    } else {
        // The managed-SSH checkbox is not a promise about third-party
        // proxies. In external mode use normal explicit SOCKS policy.
        value["remote_dns_via_ssh"] = true;
    }
    return value.dump(2);
}
void validateManagedRoute(const std::string& text,const Json& ssh,int workerCount) {
    const auto config=Json::parse(text);const auto listen=config.at("listen").get<std::string>();auto colon=listen.rfind(':');
    if(colon==std::string::npos)throw std::runtime_error("Некорректный listener FlowBridge.");
    size_t consumed=0;auto ingress=std::stoul(listen.substr(colon+1),&consumed);
    if(consumed!=listen.size()-colon-1)throw std::runtime_error("Некорректный порт FlowBridge.");
    const auto first=ssh.at("local_port").get<unsigned long>();
    for(int i=0;i<workerCount;++i)if(ingress==first+static_cast<unsigned long>(2*i))
        throw std::runtime_error("Порт FlowBridge пересекается с портом SSH-пула. Выберите другой listener.");
    auto action=config.at("default_action");if(action.value("type",std::string())!="proxy"||action.value("id",std::string())!="managed-ssh")throw std::runtime_error("Управляемый SSH должен быть первым proxy маршрута по умолчанию.");
    auto found=std::find_if(config.at("proxies").begin(),config.at("proxies").end(),[](const Json& p){return p.value("id",std::string())=="managed-ssh";});
    if(found==config.at("proxies").end()||found->value("kind",std::string())!="socks5"||found->at("endpoint").at("host")!="127.0.0.1"||found->at("endpoint").at("port")!=ssh.at("local_port"))throw std::runtime_error("Прокси маршрута не совпадает с реальным локальным endpoint управляемого SSH.");
}
struct Result { Json snapshot,ssh,acceptedDesktop; std::string error,saved;std::vector<discovery::App> apps;bool exit=false,scanned=false,waiting=false; };
class Worker {
    std::mutex mutex;
    std::condition_variable cv;
    std::thread thread;
    int command=0;
    std::string config;
    Json settings;
    uint64_t engine=0,ssh=0;
    std::vector<uint64_t> sshExtras;
    int activeWorkerCount=1;
    Json activeSsh=Json::object();
    bool waiting=false,managedActive=false;
    std::string pending;
    std::vector<uint64_t> sshIds() const {
        std::vector<uint64_t> ids;
        if(ssh)ids.push_back(ssh);
        ids.insert(ids.end(),sshExtras.begin(),sshExtras.end());
        return ids;
    }
    void destroySsh() {
        for(auto id:sshExtras)fb_ssh_destroy(id);
        sshExtras.clear();
        if(ssh)fb_ssh_destroy(ssh);
        ssh=0;activeWorkerCount=1;
    }
    void stopSsh() {
        std::string firstError;
        for(auto id:sshIds()) {
            try { response(fb_ssh_stop_json(id)); }
            catch(const std::exception& e) { if(firstError.empty())firstError=e.what(); }
        }
        if(!firstError.empty())throw std::runtime_error("Не все SSH-процессы остановились: "+firstError);
    }
    void clearManagedGate() {
        if(!engine)return;
        const Json value={{"endpoint",nullptr},{"ready",false},{"grace_ms",0}};
        response(fb_engine_set_upstream_gate_json(engine,value.dump().c_str()));
    }
    void ensureSsh(const Json& profile,int count) {
        if(ssh)return;
        std::vector<uint64_t> created;
        try {
            for(int i=0;i<count;++i) {
                auto workerProfile=profile;
                workerProfile["local_port"]=profile.at("local_port").get<int>()+2*i;
                const auto id=response(fb_ssh_create_json(workerProfile.dump().c_str()))
                    .at("ssh_id").get<uint64_t>();
                created.push_back(id);
            }
        } catch (...) {
            for(auto id:created)fb_ssh_destroy(id);
            throw;
        }
        ssh=created.front();
        sshExtras.assign(created.begin()+1,created.end());
        activeSsh=profile;activeWorkerCount=count;
    }
    void gate(bool allowed) {
        if(!engine)return;
        const int base=activeSsh.value("local_port",1080);
        if(managedActive&&activeWorkerCount>1) {
            // Rust derives each worker's port, PID and readiness from a real
            // registered supervisor. The GUI must not attest ready:true.
            const auto ids=sshIds();
            if(ids.size()!=static_cast<size_t>(activeWorkerCount))
                throw std::runtime_error("Неполный набор владельцев SSH-пула.");
            // Pause in-place with the SAME pool budgets. A temporary single
            // gate with the default 128 slots prevents the 64/42/32-slot pool
            // from being installed even before its first connection.
            const Json pool=ssh_pool_policy::ownedRequest(ids,allowed);
            response(fb_engine_sync_owned_ssh_pool_json(engine,pool.dump().c_str()));
        } else {
            // Preserve the legacy single-worker 30s reconnect grace.
            // Multi-worker pause never enters this branch.
            bool ready=allowed;
            if(managedActive) {
                const auto status=response(fb_ssh_snapshot_json(ssh)).at("status");
                ready=allowed&&status.value("state",std::string())=="ready"&&
                    status.contains("pid")&&status["pid"].is_number();
            }
            const Json value={{"endpoint",managedActive?Json{{"host","127.0.0.1"},{"port",base}}:Json(nullptr)},
                              {"ready",ready},{"grace_ms",managedActive&&activeWorkerCount>1?0:30000}};
            response(fb_engine_set_upstream_gate_json(engine,value.dump().c_str()));
        }
    }
    void accept(const std::string& value) {
        response(fb_validate_json(value.c_str()));
        if(!engine)engine=response(fb_engine_create_json(value.c_str())).at("engine_id").get<uint64_t>();
        else response(fb_engine_reload_json(engine,value.c_str()));
    }
    void run() {
        for(;;) {
            int action;std::string value;Json options;
            {
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock,[this]{return command!=0;});
                action=command;value=std::move(config);options=std::move(settings);command=0;
            }
            auto result=std::make_unique<Result>();result->exit=action==-1;
            try {
                if(action==-1) {
                    waiting=false;
                    if(engine)fb_engine_destroy(engine);
                    engine=0;destroySsh();
                } else if(action==DiscoverCommand) {
                    result->apps=discovery::scan(options);result->scanned=true;
                } else {
                    if(action==Apply&&waiting) {
                        result->error="Дождитесь запуска или нажмите «Остановить» перед изменением профиля.";
                    } else if(action==Start||action==Apply) {
                        const bool managed=options.value("managed_ssh",false);
                        validateDesktop(options);
                        if(managed)validateManagedRoute(value,options["ssh"],options.value("ssh_workers",1));
                        const bool running=engine&&response(fb_engine_snapshot_json(engine))["status"].value("running",false);
                        if(running&&managed!=managedActive)
                            throw std::runtime_error("Остановите подключение перед сменой внешнего прокси / управляемого SSH.");
                        const int desired=options.value("ssh_workers",1);
                        if(ssh&&managed&&(activeSsh!=options["ssh"]||activeWorkerCount!=desired)) {
                            if(running||waiting)
                                throw std::runtime_error("Остановите подключение перед изменением параметров SSH или числа процессов.");
                            destroySsh();
                        }
                        if(managed&&!ssh)ensureSsh(options["ssh"],desired);
                        accept(value);
                        // Release old per-worker budgets before changing pool size.
                        // The engine must be stopped; live flows cannot be migrated.
                        if(!running&&!waiting)clearManagedGate();
                        if(action==Apply) {
                            result->saved=value;result->acceptedDesktop=options;
                        }
                        if(action==Start) {
                            managedActive=managed;
                            if(managed) {
                                if(!ssh)ensureSsh(options["ssh"],desired);
                                for(auto id:sshIds()) {
                                    const auto state=response(fb_ssh_snapshot_json(id))["status"]
                                        .value("state",std::string("stopped"));
                                    if(state=="stopped"||state=="failed")
                                        response(fb_ssh_start_json(id));
                                }
                                gate(false);waiting=true;pending=value;result->acceptedDesktop=options;
                            } else {
                                if(ssh)stopSsh();
                                waiting=false;gate(true);
                                response(fb_engine_start_json(engine));
                                result->saved=value;result->acceptedDesktop=options;
                            }
                        }
                    } else if(action==Stop) {
                        waiting=false;
                        if(engine)response(fb_engine_stop_json(engine));
                        clearManagedGate();
                        // No stale gate/worker routing remains installed after Stop.
                        managedActive=false;
                        if(ssh)stopSsh();
                    }
                    if(ssh&&managedActive) {
                        result->ssh=response(fb_ssh_snapshot_json(ssh));
                        auto primary=result->ssh["status"];
                        Json workers=Json::array();
                        int readyCount=0;bool allFailed=true;
                        for(auto id:sshIds()) {
                            const auto state=response(fb_ssh_snapshot_json(id))["status"];
                            const auto mode=state.value("state",std::string());
                            if(mode=="ready")++readyCount;
                            if(mode!="failed")allFailed=false;
                            workers.push_back({{"pid",state.value("pid",Json())},
                                               {"state",mode},
                                               {"local_port",state.value("local_port",0)},
                                               {"resource_exhaustion_count",state.value("resource_exhaustion_count",uint64_t(0))},
                                               {"backend_path",state.value("backend_path",Json())}});
                        }
                        result->ssh["workers"]=workers;
                        result->ssh["status"]["ready_workers"]=readyCount;
                        result->ssh["status"]["worker_count"]=activeWorkerCount;
                        if(readyCount>0)result->ssh["status"]["state"]="ready";
                        gate(true);
                        if(waiting&&readyCount>0) {
                            response(fb_engine_start_json(engine));
                            waiting=false;result->saved=pending;
                        } else if(waiting&&allFailed) {
                            waiting=false;
                            throw std::runtime_error(primary.value("last_error",std::string("Все SSH-процессы завершились с ошибкой.")));
                        }
                    }
                    if(engine)result->snapshot=response(fb_engine_snapshot_json(engine));
                }
            } catch(const std::exception& e) {
                result->error=e.what();result->saved.clear();
                if(managedActive&&(waiting||action==Start)) {
                    waiting=false;
                    try{gate(false);}catch(...){}
                    if(engine){try{response(fb_engine_stop_json(engine));}catch(...){}}
                    if(ssh){
                        try{stopSsh();result->ssh=response(fb_ssh_snapshot_json(ssh));}catch(...){}
                        destroySsh();
                    }
                }
                try{if(engine)result->snapshot=response(fb_engine_snapshot_json(engine));}catch(...){}
            }
            result->waiting=waiting;
            if(!PostMessageW(window,Completed,0,reinterpret_cast<LPARAM>(result.get())))return;
            result.release();
            if(action==-1)return;
        }
    }
public:
    void start(){thread=std::thread([this]{run();});}
    void submit(int action,std::string value={},Json options=Json::object()) {
        {std::lock_guard<std::mutex> lock(mutex);command=action;config=std::move(value);settings=std::move(options);}
        cv.notify_one();
    }
    ~Worker(){if(thread.joinable())thread.join();}
} worker;
void enableControls() {
    for(int id:{Start,Stop,StartCapture,StopCapture,Apply,Open,Save,Proxy,Host,Port,Protocol,Config,Discover,ExportNative,ManagedMode,SshHost,SshPort,SshUser,KeyPath,KnownHosts,LocalPort,Compression,Keepalive,KeepaliveCount,SaveDesktop,BrowseKey,BrowseKnown,BrowseApp,RetryInitial,RetryMax,PresetAI,PresetWeb,PresetBoth,BlockOthers,RemoteDns,SshExecutable,BrowseSsh,SshPoolWorkers,VisualRules})EnableWindow(GetDlgItem(window,id),!busy&&!closing&&(!pendingStart||id==Stop||id==Discover||id==BrowseApp||id==PresetAI||id==PresetWeb||id==PresetBoth||id==BlockOthers));
    EnableWindow(GetDlgItem(window,Start),!busy&&!closing&&!engineRunning&&!pendingStart&&!nativeCapture.active());
    const bool managed=SendMessageW(GetDlgItem(window,ManagedMode),CB_GETCURSEL,0,0)==1;
    EnableWindow(GetDlgItem(window,StartCapture),ssh_pool_policy::captureAvailable(
        managed,engineRunning,pendingStart,tunnelReady,busy,closing,
        nativeCapture.active(),nativeCapture.stopping()));
    EnableWindow(GetDlgItem(window,StopCapture),!closing&&nativeCapture.active());
    setText(GetDlgItem(window,Start),pendingStart?"Подключаем…":engineRunning?"Подключено":"Подключить");
}
void dispatch(int action,std::string text={},Json options=Json::object()){busy=true;if(action!=PollCommand)enableControls();worker.submit(action,std::move(text),std::move(options));}
// The ordinary GUI owns the SSH transport; on exit the privileged capture
// filters must be fully withdrawn before the user-owned SSH is torn down.
void finishCloseAfterCapture(){
    if(!closing||busy||nativeCapture.active()||nativeCapture.stopping()||shutdownDispatched)return;
    shutdownDispatched=true;
    KillTimer(window,1);
    dispatch(-1);
}
std::wstring display(const Json& j,const char* name) {
    if(!j.contains(name)||j[name].is_null())return L"";
    auto text=j[name].is_string()?j[name].get<std::string>():j[name].dump();
    if(std::string(name)=="state"){const std::map<std::string,std::string> labels={{"completed","Завершено"},{"active","Активно"},{"connecting","Подключение"},{"waiting_for_tunnel","Ожидание SSH"},{"failed","Ошибка"},{"blocked","Блокировано"}};auto found=labels.find(text);if(found!=labels.end())text=found->second;}
    if(std::string(name)=="rule"&&text=="default")text="По умолчанию";
    if(std::string(name)=="action"){if(text=="direct")text="Напрямую";else if(text=="block")text="Блокировать";else if(text.rfind("proxy:",0)==0)text="Прокси: "+text.substr(6);else if(text.rfind("chain:",0)==0)text="Цепочка: "+text.substr(6);}
    return wide(text);
}
void showSnapshot(const Json& snap) {
    latestEngineSnapshot=snap;
    if(snap.is_null()) return;
    const auto& status=snap.at("status"); bool running=status.value("running",false); engineRunning=running;
    auto text=std::string(running?"Подключено":"Остановлено")+" | SOCKS5: "+status.value("listen",std::string(""))+" | Активно: "+std::to_string(status.value("active",0))+" | Всего: "+std::to_string(status.value("accepted",0))+" | Ошибок: "+std::to_string(status.value("failed",0));
    if(!workerError.empty()) text+=" | Ошибка: "+workerError;
    setText(GetDlgItem(window,Status),text);
    setText(GetDlgItem(window,Badge),running?"●  Локальный SOCKS5 работает":"●  Не подключено");
    setText(GetDlgItem(window,Metrics),"АКТИВНЫЕ СОЕДИНЕНИЯ     "+std::to_string(status.value("active",0))+"       ПРИНЯТО     "+std::to_string(status.value("accepted",0))+"       ТРАФИК ↑ / ↓     "+std::to_string(status.value("bytes_up",uint64_t(0)))+" / "+std::to_string(status.value("bytes_down",uint64_t(0)))+" Б");
    InvalidateRect(GetDlgItem(window,Badge),nullptr,TRUE);
    ListView_DeleteAllItems(table); int row=0;
    for(const auto& connection:snap.value("connections",Json::array())) {
        auto route=display(connection,"action");
        if(connection.contains("worker_port")&&!connection["worker_port"].is_null())
            route+=L" · SSH:"+display(connection,"worker_port");
        std::wstring fields[]={display(connection,"id"), display(connection,"host")+L":"+display(connection,"port"),display(connection,"rule"),route,display(connection,"state"),display(connection,"bytes_up")+L" / "+display(connection,"bytes_down"),display(connection,"error")};
        LVITEMW item{}; item.mask=LVIF_TEXT; item.iItem=row; item.pszText=fields[0].data(); ListView_InsertItem(table,&item);
        for(int col=1;col<7;++col) ListView_SetItemText(table,row,col,fields[col].data()); ++row;
    }
    std::string events=localLog;
    for(const auto& event:snap.value("events",Json::array())) events+="["+event.value("level",std::string("info"))+"] "+event.value("message",std::string(""))+"\r\n";
    if(events.size()>60000) events.erase(0,events.size()-60000);
    // Byte truncation can split UTF-8; drop at most the leading continuation bytes.
    while(!events.empty() && (static_cast<unsigned char>(events[0])&0xc0)==0x80) events.erase(0,1);
    setText(logEdit,events);
}
void fileDialog(bool saving) {
    wchar_t path[32768]{}; OPENFILENAMEW info{}; info.lStructSize=sizeof(info); info.hwndOwner=window;
    info.lpstrFilter=L"JSON profiles\0*.json\0All files\0*.*\0"; info.lpstrFile=path; info.nMaxFile=32768; info.lpstrDefExt=L"json";
    info.Flags=OFN_EXPLORER|OFN_NOCHANGEDIR|(saving?OFN_OVERWRITEPROMPT:OFN_FILEMUSTEXIST);
    if(!(saving?GetSaveFileNameW(&info):GetOpenFileNameW(&info))) return;
    if(saving) { writeFile(path,configuration()); note("Черновик JSON экспортирован. Подключить / Применить проверяет и сохраняет активный профиль."); }
    else { auto value=readFile(path); auto parsed=Json::parse(value); (void)parsed; setText(configEdit,value); fillQuick(); note("Черновик загружен. Нажмите «Применить профиль» для проверки и сохранения."); }
}
COLORREF bg(){return dark?RGB(17,24,39):RGB(244,247,252);}COLORREF card(){return dark?RGB(28,39,57):RGB(255,255,255);}COLORREF ink(){return dark?RGB(232,239,250):RGB(27,42,66);}COLORREF muted(){return dark?RGB(162,179,201):RGB(98,116,140);}
void applyTheme(){
    if(backgroundBrush)DeleteObject(backgroundBrush);
    if(cardBrush)DeleteObject(cardBrush);
    if(sidebarBrush)DeleteObject(sidebarBrush);
    backgroundBrush=CreateSolidBrush(bg());cardBrush=CreateSolidBrush(card());sidebarBrush=CreateSolidBrush(RGB(18,30,52));
    for(int id:{Connections,AppsTable}){HWND list=GetDlgItem(window,id);ListView_SetBkColor(list,card());ListView_SetTextBkColor(list,card());ListView_SetTextColor(list,ink());}
    InvalidateRect(window,nullptr,TRUE);RedrawWindow(window,nullptr,nullptr,RDW_INVALIDATE|RDW_ALLCHILDREN|RDW_ERASE);
}
void updateVisibility(){
    const bool managed=SendMessageW(GetDlgItem(window,ManagedMode),CB_GETCURSEL,0,0)==1;
    // Connection controls use subpage 11 (external proxy) and 12 (managed
    // SSH). Apply this to labels and help as well as input widgets: the
    // previous ID-range check left all descriptive labels hidden.
    for(const auto& pair:pages) {
        bool visible=pair.second<0||pair.second==activePage;
        if(pair.second==11) visible=activePage==1&&!managed;
        if(pair.second==12) visible=activePage==1&&managed;
        ShowWindow(GetDlgItem(window,pair.first),visible?SW_SHOW:SW_HIDE);
    }
}
void switchPage(int page){activePage=page;
    const char* titles[]={"Обзор подключения","Подключение","Приложения и шаблоны","Настройки и журнал"};
    const char* subtitles[]={"Ваш локальный маршрут. Состояние SSH и реальные соединения в одном месте.","Используйте готовый прокси или доверьте FlowBridge запуск и восстановление SSH.","Найдите приложения на этом компьютере и подготовьте выбор для нативного захвата.","Полный профиль маршрутизации, правила, цепочки и последние события движка."};
    setText(GetDlgItem(window,PageTitle),titles[page]);setText(GetDlgItem(window,PageSubtitle),subtitles[page]);updateVisibility();layout();InvalidateRect(window,nullptr,TRUE);
    if(page==2&&!discoveryDone&&!busy){setText(GetDlgItem(window,ScanStatus),"Ищем приложения локально…");dispatch(DiscoverCommand,{},catalog);}
}
void captureSelections(){if(loadingApps||(!discoveryDone&&discovered.empty()))return;selectedApps.clear();for(size_t i=0;i<discovered.size();++i)if(ListView_GetCheckState(GetDlgItem(window,AppsTable),static_cast<int>(i)))selectedApps.insert(discovered[i].path);}
void refreshApps(){
    loadingApps=true;HWND list=GetDlgItem(window,AppsTable);ListView_DeleteAllItems(list);int row=0;
    for(const auto& app:discovered){std::wstring fields[]={wide(app.name),wide(app.path),wide(app.source),wide(std::to_string(app.confidence)+"% • эвристика")};LVITEMW item{};item.mask=LVIF_TEXT;item.iItem=row;item.pszText=fields[0].data();ListView_InsertItem(list,&item);for(int col=1;col<4;++col)ListView_SetItemText(list,row,col,fields[col].data());ListView_SetCheckState(list,row,selectedApps.count(app.path)?TRUE:FALSE);++row;}
    loadingApps=false;setText(GetDlgItem(window,AppsSummary),"Найдено: "+std::to_string(discovered.size())+"   •   Выбрано: "+std::to_string(selectedApps.size())+"   •   Сопоставление по имени EXE, без проверки издателя");
}
void choosePreset(const std::string& preset){captureSelections();selectedPreset=preset;std::set<std::string> ids;
    for(const auto& p:catalog.value("presets",Json::array()))if(p.value("id",std::string())==preset)for(const auto& id:p.value("app_ids",std::vector<std::string>{}))ids.insert(id);
    selectedApps.clear();for(const auto& app:discovered)if(ids.count(app.id)&&app.confidence>=80)selectedApps.insert(app.path);refreshApps();
    try{saveDesktop();}catch(const std::exception& e){note(e.what());}InvalidateRect(window,nullptr,TRUE);
}
std::filesystem::path chooseFile(const wchar_t* filter,bool saving,const wchar_t* extension=L"json"){
    wchar_t path[32768]{};OPENFILENAMEW info{};info.lStructSize=sizeof(info);info.hwndOwner=window;info.lpstrFilter=filter;info.lpstrFile=path;info.nMaxFile=32768;info.lpstrDefExt=extension;info.Flags=OFN_EXPLORER|OFN_NOCHANGEDIR|(saving?OFN_OVERWRITEPROMPT:OFN_FILEMUSTEXIST);if(!(saving?GetSaveFileNameW(&info):GetOpenFileNameW(&info)))return {};return path;
}
void exportDiagnostics(){
    auto engine=latestEngineSnapshot.is_object()?latestEngineSnapshot:Json::object();
    auto ssh=latestSshSnapshot.is_object()?latestSshSnapshot:Json::object();
    auto request=Json{{"engine",{{"status",engine.value("status",Json::object())},
        {"managed_upstream",engine.value("managed_upstream",Json())},
        {"managed_pool",engine.value("managed_pool",Json())}}},
        {"ssh",{{"status",ssh.value("status",Json::object())}}}}.dump();
    auto report=response(fb_diagnostic_report_json(request.c_str())).at("report");
    auto path=chooseFile(L"Диагностический JSON\0*.json\0",true);
    if(path.empty())return;
    writeFile(path,report.dump(2));
    note("Диагностический отчёт сохранён: без ключей, адресов, путей и сырых журналов.");
}
void browseApplication(){auto path=chooseFile(L"Приложения Windows\0*.exe\0",false,L"exe");if(path.empty())return;
    auto text=discovery::utf8(path.wstring());auto found=std::find_if(discovered.begin(),discovered.end(),[&](const discovery::App& a){return a.path==text;});if(found==discovered.end())discovered.push_back({"manual",discovery::utf8(path.stem().wstring()),text,"Выбрано вручную",100});selectedApps.insert(text);refreshApps();saveDesktop();
}
void startNativeCapture(){
    captureSelections();
    if(nativeCapture.active()||nativeCapture.stopping())
        throw std::runtime_error("Дождитесь завершения предыдущего нативного перехвата.");
    if(selectedApps.empty())throw std::runtime_error("Выберите хотя бы один существующий EXE.");
    if(selectedApps.size()>64)throw std::runtime_error("Нативный режим поддерживает максимум 64 EXE.");
    if(SendMessageW(GetDlgItem(window,BlockOthers),BM_GETCHECK,0,0)==BST_CHECKED)
        throw std::runtime_error("Блокировка всех остальных приложений не реализована на системном уровне. Уберите галочку.");
    auto settings=desktopSettings();validateDesktop(settings);
    const bool managed=settings.value("managed_ssh",false);
    auto base=Json::parse(commandConfiguration());
    auto selected=std::vector<std::string>(selectedApps.begin(),selectedApps.end());
    std::vector<std::wstring> bypass;
    wchar_t exe[32768]{};
    const DWORD count=GetModuleFileNameW(nullptr,exe,32768);
    if(!count||count>=32768)throw std::runtime_error("Не удалось определить путь текущего FlowBridge.exe.");
    bypass.emplace_back(exe,count);
    if(managed) {
        // Do not start an SSH client or load private keys in the UAC-elevated
        // helper. The ordinary GUI's worker owns the OpenSSH watchdog and
        // already gates its loopback SOCKS ingress on actual SSH readiness.
        if(!engineRunning||pendingStart||!tunnelReady)
            throw std::runtime_error("Сначала нажмите «Подключить» и дождитесь готовности SSH. Нативный перехват использует этот пользовательский SSH-сеанс.");
        validateManagedRoute(base.dump(),settings.at("ssh"),settings.value("ssh_workers",1));
        const auto actual=latestEngineSnapshot.value("status",Json::object());
        if(actual.value("listen",std::string())!=base.at("listen").get<std::string>())
            throw std::runtime_error("Изменён локальный SOCKS-порт. Сначала примените новый профиль и дождитесь готовности.");
        const auto sshStatus=latestSshSnapshot.value("status",Json::object());
        if(sshStatus.value("state",std::string())!="ready")
            throw std::runtime_error("Нет готового пользовательского SSH-процесса.");
        // Each independent backend must be excluded by its actual verified
        // executable path: never elevate or re-intercept a user's ssh.exe.
        std::set<std::wstring> excluded;
        const auto workers=latestSshSnapshot.value("workers",Json::array());
        if(!workers.empty()) {
            for(const auto& worker:workers) {
                if(worker.value("state",std::string())!="ready")continue;
                if(!worker.contains("backend_path")||!worker["backend_path"].is_string())
                    throw std::runtime_error("Готовый SSH-процесс не предоставил проверенный путь exe.");
                excluded.insert(wide(worker["backend_path"].get<std::string>()));
            }
        } else if(sshStatus.contains("backend_path")&&sshStatus["backend_path"].is_string()) {
            excluded.insert(wide(sshStatus["backend_path"].get<std::string>()));
        }
        if(excluded.empty())
            throw std::runtime_error("Нет ни одного готового проверенного OpenSSH exe.");
        for(const auto& sshExe:excluded) {
            if(!std::filesystem::path(sshExe).is_absolute()||!std::filesystem::is_regular_file(sshExe))
                throw std::runtime_error("Исполняемый файл пользовательского SSH не найден.");
            bypass.push_back(sshExe);
        }
        base=native_profile::viaUserOwnedSsh(std::move(base),selected);
    } else {
        if(engineRunning||pendingStart)
            throw std::runtime_error("Остановите локальный SOCKS перед отдельным перехватом через внешний прокси.");
        if(selectedProxyId.empty())
            throw std::runtime_error("Укажите SOCKS upstream в разделе подключения.");
        base=native_profile::build(std::move(base),selected,selectedProxyId,false);
    }
    const auto value=base.dump(2);
    response(fb_validate_json(value.c_str()));
    auto dir=desktopPath.parent_path();
    if(dir.empty())throw std::runtime_error("Нет папки пользовательских настроек.");
    const auto nativeProfile=dir/L"native-capture.json";
    writeFile(nativeProfile,value);
    std::vector<std::wstring> apps;apps.reserve(selectedApps.size());
    for(const auto& path:selectedApps)apps.push_back(wide(path));
    // GUI-originated native capture MUST pass an empty --ssh-profile.
    nativeCapture.start(nativeProfile.wstring(),L"",apps,bypass,profile_integrity::sha256(value));
    saveDesktop();
    setText(GetDlgItem(window,CaptureStatus),
        managed?"WFP helper запускается через UAC; SSH и ключи остаются в обычном процессе FlowBridge."
               :"WFP helper запускается через UAC; готовность внешнего SOCKS и WFP проверяются отдельно.");
    note("Нативный helper запрошен для "+std::to_string(apps.size())+
         " EXE; маршрут: "+(managed?"пользовательский SSH через локальный SOCKS":"внешний прокси")+
         ". Драйвер/реальное перенаправление требуют отдельной проверки.");
}
void stopNativeCapture(){
    if(!nativeCapture.active()) {note("Нативный helper уже остановлен.");return;}
    nativeCapture.stop();
    setText(GetDlgItem(window,CaptureStatus),"Останавливаем helper: снимаются WFP-фильтры и закрываются соединения.");
    note("Запрошена остановка нативного перехвата.");
}
void exportProxiFyre() {
    captureSelections();
    if(selectedApps.empty())
        throw std::runtime_error("Сначала отметьте приложения для экспорта в ProxiFyre.");
    const auto source=commandConfiguration();
    response(fb_validate_json(source.c_str()));
    auto output=proxifyre_export::build(Json::parse(source),
        std::vector<std::string>(selectedApps.begin(),selectedApps.end()),
        SendMessageW(GetDlgItem(window,BlockOthers),BM_GETCHECK,0,0)==BST_CHECKED);
    auto path=chooseFile(L"ProxiFyre app-config JSON\0*.json\0",true);
    if(path.empty())return;
    writeFile(path,output.dump(2));
    saveDesktop();
    note("Экспорт ProxiFyre завершён. Установите официальный ProxiFyre/Windows Packet Filter отдельно. Только выбранные TCP; DNS и UDP/QUIC не защищены.");
}
void showSsh(const Json& ssh,bool waiting){
    latestSshSnapshot=ssh;
    if(ssh.is_null()){bool managed=SendMessageW(GetDlgItem(window,ManagedMode),CB_GETCURSEL,0,0)==1;tunnelReady=!managed;setText(GetDlgItem(window,SshHealth),managed?"Управляемый SSH не запущен":"SSH: используется внешний прокси");setText(GetDlgItem(window,SshSummary),managed?"SSH запустится после нажатия «Подключить». Ключ сервера должен быть заранее проверен.":"Внешний прокси управляется отдельно от FlowBridge.");return;}
    auto status=ssh.at("status");auto state=status.value("state",std::string("stopped"));tunnelReady=state=="ready";std::string label=state=="ready"?"Готов":state=="starting"?"Запускается":state=="reconnecting"?"Восстанавливается":state=="degraded"?"Перегрузка / диагностика":state=="failed"?"Требуется внимание":"Остановлен";
    const int workers=status.value("worker_count",1);
    const int ready=status.value("ready_workers",state=="ready"?1:0);
    std::string text="SSH "+std::to_string(ready)+"/"+std::to_string(workers)+" • "+label+
        " • перезапусков "+std::to_string(status.value("restarts",uint64_t(0)));
    if(status.contains("last_error")&&!status["last_error"].is_null())text+="\n"+status["last_error"].get<std::string>();
    uint64_t aggregateErrors=0;
    for(const auto& worker:ssh.value("workers",Json::array()))
        aggregateErrors+=worker.value("resource_exhaustion_count",uint64_t(0));
    text+="\nОшибок ресурсов: "+std::to_string(workers>1?aggregateErrors:status.value("resource_exhaustion_count",uint64_t(0)));
    if(workers>1) {
        text+=" | порты: ";
        for(const auto& worker:ssh.value("workers",Json::array()))
            text+=std::to_string(worker.value("local_port",0))+
                (worker.value("state",std::string())=="ready"?"✓ ":"× ");
    }
    if(status.contains("backend_path")&&!status["backend_path"].is_null())text+=" · "+status["backend_path"].get<std::string>();
    if(status.contains("backend_version")&&!status["backend_version"].is_null())text+=" · "+status["backend_version"].get<std::string>();
    const auto pool=latestEngineSnapshot.value("managed_pool",Json());
    if(pool.is_object()) {
        uint64_t active=0,queued=0,rejected=0;
        for(const auto& worker:pool.value("workers",Json::array())) {
            const auto counters=worker.value("admission",Json::object());
            active+=counters.value("active_including_opening",uint64_t(0));
            queued+=counters.value("queued",uint64_t(0));
            rejected+=counters.value("rejected",uint64_t(0));
        }
        text+="\nКаналов: "+std::to_string(active)+"/"+
            std::to_string(pool.value("aggregate_max_flows",128))+
            " · очередь: "+std::to_string(queued)+
            " · отказов: "+std::to_string(rejected);
    }
    setText(GetDlgItem(window,SshHealth),text);setText(GetDlgItem(window,SshSummary),text);
    if(waiting){setText(GetDlgItem(window,Badge),"●  Ожидание готовности SSH");setText(GetDlgItem(window,Status),"Сначала проверяется SSH/SOCKS5. Локальный движок запустится после подтверждения готовности.");}
    if(engineRunning&&!tunnelReady){setText(GetDlgItem(window,Badge),state=="degraded"?"●  SSH перегружен / проверяется · новые соединения ждут":"●  SSH восстанавливается · SOCKS ждёт upstream");}
    std::string events=utf8(logEdit);for(const auto& event:ssh.value("events",Json::array()))events+="\r\n[SSH / "+event.value("level",std::string("info"))+"] "+event.value("message",std::string());if(events.size()>60000)events.erase(0,events.size()-60000);while(!events.empty()&&(static_cast<unsigned char>(events[0])&0xc0)==0x80)events.erase(0,1);setText(logEdit,events);
}

HWND control(const wchar_t* cls,const wchar_t* label,DWORD style,int id,DWORD ex=0) {
    if(wcscmp(cls,L"BUTTON")==0 && (style&BS_TYPEMASK)!=BS_AUTOCHECKBOX)style=(style&~BS_TYPEMASK)|BS_OWNERDRAW;
    auto h=CreateWindowExW(ex,cls,label,WS_CHILD|WS_VISIBLE|style,0,0,0,0,window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
    SendMessageW(h,WM_SETFONT,reinterpret_cast<WPARAM>(bodyFont),TRUE); return h;
}
void layout() {
    RECT r{}; GetClientRect(window,&r);
    const int width=static_cast<int>(r.right),height=static_cast<int>(r.bottom);
    const int x=236,w=width-x-28;
    auto move=[](int id,int left,int top,int cw,int ch) {
        MoveWindow(GetDlgItem(window,id),left,top,std::max(1,cw),std::max(1,ch),TRUE);
    };
    for(int id=NavDashboard;id<=NavAdvanced;++id)move(id,16,140+(id-NavDashboard)*54,180,44);
    move(Theme,16,height-70,180,40);
    move(ExportDiagnostics,16,height-120,180,40);
    move(Banner,x,100,w,19);move(PageTitle,x,24,w-330,36);
    move(PageSubtitle,x,70,w,25);
    move(Start,width-322,24,160,40);move(Stop,width-150,24,122,40);
    // Dashboard: the connection list and help must remain visible at 1280x720.
    move(Badge,x+24,143,w-48,30);move(Status,x+24,185,w-48,28);
    move(Mode,x+24,224,w-48,30);move(Metrics,x+24,280,w-48,24);
    move(SshTitle,x+24,319,w-48,22);move(SshHealth,x+24,347,w-48,46);
    move(ConnectionsLabel,x,411,w,24);
    move(Connections,x,441,w,std::max(80,height-486));
    move(DashboardHelp,x,height-32,w,24);
    // Connection: compact two-column SSH fields (no hidden form below the screen).
    move(ConnectionSummary,x+24,137,210,24);
    move(ManagedMode,x+244,132,w-268,220);move(SshSummary,x+24,174,w-48,34);
    move(QuickLabel,x+24,227,140,22);move(Proxy,x+180,221,240,220);
    move(2000,x+24,285,300,22);move(2001,x+348,285,100,22);
    move(2002,x+472,285,200,22);
    move(Host,x+24,313,300,32);move(Port,x+348,313,100,32);
    move(Protocol,x+472,313,std::min(235,w-496),220);
    move(2003,x+24,371,w-48,48);
    const int half=(w-72)/2;
    move(2010,x+24,217,half,18);move(2011,x+48+half,217,half,18);
    move(SshHost,x+24,239,half,28);move(SshUser,x+48+half,239,half,28);
    move(2012,x+24,275,half,18);move(2013,x+48+half,275,half,18);
    move(SshPort,x+24,297,half,28);move(LocalPort,x+48+half,297,half,28);
    move(2014,x+24,333,w-48,18);move(KeyPath,x+24,355,w-182,28);
    move(BrowseKey,x+w-142,355,118,28);
    move(2015,x+24,391,w-48,18);move(KnownHosts,x+24,413,w-182,28);
    move(BrowseKnown,x+w-142,413,118,28);
    move(Compression,x+24,450,110,24);
    move(SshPoolLabel,x+140,450,82,22);
    move(SshPoolWorkers,x+226,446,62,145);
    move(SshExecutable,x+302,449,w-472,28);
    move(BrowseSsh,x+w-142,449,118,28);
    const int unit=(w-120)/4;
    const int labels[]={2016,2017,2019,2020};
    const int fields[]={Keepalive,KeepaliveCount,RetryInitial,RetryMax};
    for(int i=0;i<4;++i) {
        move(labels[i],x+24+i*(unit+24),482,unit,18);
        move(fields[i],x+24+i*(unit+24),504,unit,28);
    }
    move(SshHelp,x+24,540,w-48,34);
    // DNS scope is deliberately limited to explicit SOCKS hostname input.
    // Keep the toggle and Save button horizontally separate at 980x680.
    move(RemoteDns,x+24,height-58,w-290,26);
    move(SaveDesktop,x+w-230,height-56,230,36);
    // Applications: four equal-flow buttons and a table that yields space to
    // the status/actions footer rather than being clipped by it.
    move(AppsHelp,x+24,139,w-48,54);
    const int presetWidth=w<850?std::max(130,(w-36)/4):180;
    const int discoverWidth=std::min(210,w-3*(presetWidth+12));
    move(PresetAI,x,211,presetWidth,38);
    move(PresetWeb,x+presetWidth+12,211,presetWidth,38);
    move(PresetBoth,x+2*(presetWidth+12),211,presetWidth,38);
    move(Discover,x+w-discoverWidth,211,discoverWidth,38);
    move(ScanStatus,x,259,w,22);move(AppsSummary,x,293,w-180,22);
    move(BrowseApp,x+w-172,283,172,34);
    move(AppsTable,x,332,w,std::max(85,height-550));
    move(2018,x,height-210,w,32);
    move(CaptureStatus,x+24,height-169,w-48,35);
    move(BlockOthers,x+24,height-127,w-48,26);
    const int buttonWidth=(w-24)/3;
    move(StartCapture,x,height-86,buttonWidth,40);
    move(StopCapture,x+buttonWidth+12,height-86,buttonWidth,40);
    move(ExportNative,x+2*(buttonWidth+12),height-86,w-2*(buttonWidth+12),40);
    // Advanced JSON/log split is derived from the actual available height.
    move(Apply,x,132,160,38);move(VisualRules,x+170,132,170,38);
    move(Open,x+350,132,160,38);move(Save,x+520,132,160,38);move(ConfigLabel,x,190,w,30);
    const int editor=std::max(150,(height-330)*3/5);
    move(Config,x,226,w,editor);move(LogLabel,x,240+editor,w,24);
    move(Log,x,272+editor,w,std::max(100,height-editor-302));
}
LRESULT CALLBACK windowProc(HWND h,UINT message,WPARAM w,LPARAM l) {
    switch(message) {
    case WM_CREATE: {
        window=h;
        auto add=[](const wchar_t* cls,const wchar_t* text,DWORD style,int id,int page){HWND c=control(cls,text,style,id);pages[id]=page;return c;};
        auto label=[&](const wchar_t* text,int id,int page){return add(L"STATIC",text,0,id,page);};
        label(L"",PageTitle,-1);label(L"",PageSubtitle,-1);label(L"",Banner,-1);SendMessageW(GetDlgItem(h,Banner),WM_SETFONT,reinterpret_cast<WPARAM>(smallFont),TRUE);SendMessageW(GetDlgItem(h,PageTitle),WM_SETFONT,reinterpret_cast<WPARAM>(titleFont),TRUE);
        add(L"BUTTON",L"Обзор",WS_TABSTOP,NavDashboard,-1);add(L"BUTTON",L"Подключение",WS_TABSTOP,NavConnection,-1);add(L"BUTTON",L"Приложения",WS_TABSTOP,NavApps,-1);add(L"BUTTON",L"Журнал и JSON",WS_TABSTOP,NavAdvanced,-1);add(L"BUTTON",L"Сменить тему",WS_TABSTOP,Theme,-1);
        add(L"BUTTON",L"Диагностика…",WS_TABSTOP,ExportDiagnostics,-1);
        add(L"BUTTON",L"Подключить",WS_TABSTOP,Start,-1);add(L"BUTTON",L"Остановить",WS_TABSTOP,Stop,-1);
        label(L"●  Не подключено",Badge,0);SendMessageW(GetDlgItem(h,Badge),WM_SETFONT,reinterpret_cast<WPARAM>(headingFont),TRUE);
        label(L"Остановлено. Выберите подключение и нажмите «Подключить».",Status,0);
        label(L"Локальный SOCKS5 работает отдельно. Нативный перехват выбранных EXE доступен через UAC при установленном WFP-драйвере.",Mode,0);
        label(L"АКТИВНЫЕ СОЕДИНЕНИЯ     0       ПРИНЯТО     0       ТРАФИК ↑ / ↓     0 / 0 Б",Metrics,0);
        label(L"Состояние SSH",SshTitle,0);label(L"SSH: используется внешний прокси",SshHealth,0);
        label(L"Текущие и недавние соединения",ConnectionsLabel,0);
        label(L"Существующие TCP-соединения не восстанавливаются после обрыва SSH.",DashboardHelp,0);
        label(L"Способ подключения",ConnectionSummary,1);
        HWND mode=add(L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP,ManagedMode,1);SendMessageW(mode,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(L"Готовый внешний прокси"));SendMessageW(mode,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(L"SSH с автовосстановлением"));SendMessageW(mode,CB_SETCURSEL,0,0);
        label(L"Прокси",QuickLabel,11);add(L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP|WS_VSCROLL,Proxy,11);
        label(L"Хост upstream-прокси",2000,11);label(L"Порт",2001,11);label(L"Протокол",2002,11);
        add(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,Host,11);add(L"EDIT",L"",WS_BORDER|ES_NUMBER|WS_TABSTOP,Port,11);
        HWND protocol=add(L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP,Protocol,11);for(auto item:{L"SOCKS5",L"HTTP CONNECT",L"SOCKS4a"})SendMessageW(protocol,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(item));
        label(L"FlowBridge не запускает внешний прокси. Убедитесь, что он доступен до подключения.",2003,11);
        label(L"SSH-сервер",2010,12);label(L"Пользователь",2011,12);label(L"Порт SSH",2012,12);label(L"Локальный SOCKS-порт",2013,12);
        label(L"Приватный ключ (пусто — SSH agent)",2014,12);label(L"known_hosts (пусто — стандартный файл OpenSSH)",2015,12);label(L"Keepalive, сек.",2016,12);label(L"Пропусков",2017,12);label(L"Повтор SSH, мс",2019,12);label(L"Макс. пауза, мс",2020,12);
        for(int id:{SshHost,SshUser,KeyPath,KnownHosts,SshExecutable})add(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,id,12);
        for(int id:{SshPort,LocalPort,Keepalive,KeepaliveCount,RetryInitial,RetryMax})add(L"EDIT",L"",WS_BORDER|ES_NUMBER|WS_TABSTOP,id,12);
        add(L"BUTTON",L"Сжатие SSH",BS_AUTOCHECKBOX|WS_TABSTOP,Compression,12);
        label(L"Процессов",SshPoolLabel,12);
        HWND count=add(L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP,SshPoolWorkers,12);
        for(const wchar_t* number:{L"1",L"2",L"3",L"4"})
            SendMessageW(count,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(number));
        SendMessageW(count,CB_SETCURSEL,0,0);
        add(L"BUTTON",L"Разрешать DNS на удалённом SSH-сервере",BS_AUTOCHECKBOX|WS_TABSTOP,RemoteDns,12);
        SendMessageW(GetDlgItem(h,SshExecutable),EM_SETCUEBANNER,TRUE,
                     reinterpret_cast<LPARAM>(L"Путь ssh.exe · пусто = PATH"));
        add(L"BUTTON",L"Выбрать…",WS_TABSTOP,BrowseKey,12);add(L"BUTTON",L"Выбрать…",WS_TABSTOP,BrowseKnown,12);
        add(L"BUTTON",L"SSH exe…",WS_TABSTOP,BrowseSsh,12);
        label(L"SSH: ключ сервера проверьте в known_hosts. DNS: только hostname в явном SOCKS5; без галочки имена блокируются, локального обхода нет. Прозрачный WFP DNS не защищён.",SshHelp,12);
        label(L"Внешний прокси управляется отдельно от FlowBridge.",SshSummary,1);
        add(L"BUTTON",L"Сохранить подключение",WS_TABSTOP,SaveDesktop,1);
        label(L"Windows: подключите SSH, отметьте EXE и экспортируйте профиль для ProxiFyre. Microsoft-подписанный Windows Packet Filter устанавливается отдельно; WFP FlowBridge — экспериментальный.",AppsHelp,2);
        add(L"BUTTON",L"AI-приложения",WS_TABSTOP,PresetAI,2);add(L"BUTTON",L"Веб-браузеры",WS_TABSTOP,PresetWeb,2);add(L"BUTTON",L"AI + веб",WS_TABSTOP,PresetBoth,2);
        add(L"BUTTON",L"Найти приложения",WS_TABSTOP,Discover,2);add(L"BUTTON",L"Добавить EXE…",WS_TABSTOP,BrowseApp,2);
        label(L"Поиск локальный: App Paths, список установки, известные ярлыки и запущенные процессы.",ScanStatus,2);label(L"Найдено: 0 • Выбрано: 0",AppsSummary,2);
        HWND apps=add(WC_LISTVIEWW,L"",WS_BORDER|LVS_REPORT|LVS_SINGLESEL|WS_TABSTOP,AppsTable,2);ListView_SetExtendedListViewStyle(apps,LVS_EX_FULLROWSELECT|LVS_EX_CHECKBOXES|LVS_EX_DOUBLEBUFFER);
        const wchar_t* appTitles[]={L"Приложение",L"Обнаруженный путь",L"Источник",L"Уверенность"};int appWidths[]={160,420,150,160};for(int i=0;i<4;++i){LVCOLUMNW col{};col.mask=LVCF_TEXT|LVCF_WIDTH;col.pszText=const_cast<wchar_t*>(appTitles[i]);col.cx=appWidths[i];ListView_InsertColumn(apps,i,&col);}
        label(L"ProxiFyre: выбранные EXE через SOCKS, остальные — напрямую. DNS/UDP/QUIC не защищены; сопоставление пути — подстрока.",2018,2);
        add(L"BUTTON",L"Блокировать остальные приложения вместо Direct",BS_AUTOCHECKBOX|WS_TABSTOP,BlockOthers,2);add(L"BUTTON",L"Экспорт ProxiFyre…",WS_TABSTOP,ExportNative,2);
        add(L"BUTTON",L"Экспериментальный WFP…",WS_TABSTOP,StartCapture,2);
        add(L"BUTTON",L"Остановить WFP",WS_TABSTOP,StopCapture,2);
        label(L"Перехват не запущен. Для Windows 10/11 используйте отдельно установленный ProxiFyre; собственный WFP-драйвер не входит в пакет.",CaptureStatus,2);
        add(L"BUTTON",L"Применить профиль",WS_TABSTOP,Apply,3);add(L"BUTTON",L"Правила…",WS_TABSTOP,VisualRules,3);add(L"BUTTON",L"Открыть JSON…",WS_TABSTOP,Open,3);add(L"BUTTON",L"Экспорт JSON…",WS_TABSTOP,Save,3);
        label(L"Полный профиль • правила / цепочки / listener. Критерии приложений неприменимы в локальном SOCKS-режиме.",ConfigLabel,3);
        configEdit=add(L"EDIT",L"",WS_BORDER|WS_VSCROLL|WS_HSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_AUTOHSCROLL|ES_WANTRETURN|WS_TABSTOP,Config,3);SendMessageW(configEdit,EM_SETLIMITTEXT,MaxBytes,0);
        label(L"Журнал движка и SSH • последние события",LogLabel,3);logEdit=add(L"EDIT",L"",WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,Log,3);SendMessageW(logEdit,EM_SETLIMITTEXT,65536,0);
        table=add(WC_LISTVIEWW,L"",WS_BORDER|LVS_REPORT|LVS_SINGLESEL|WS_TABSTOP,Connections,0);ListView_SetExtendedListViewStyle(table,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
        const wchar_t* titles[]={L"ID",L"Назначение",L"Правило",L"Маршрут",L"Состояние",L"↑ / ↓, байт",L"Ошибка"};int widths[]={48,190,145,130,130,135,180};for(int i=0;i<7;++i){LVCOLUMNW col{};col.mask=LVCF_TEXT|LVCF_WIDTH;col.pszText=const_cast<wchar_t*>(titles[i]);col.cx=widths[i];ListView_InsertColumn(table,i,&col);}
        std::string value=initialConfig;
        try{PWSTR path=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData,KF_FLAG_CREATE,nullptr,&path)))throw std::runtime_error("Не удалось найти Local AppData.");profile=std::filesystem::path(path)/L"FlowBridge"/L"profile.json";CoTaskMemFree(path);desktopPath=profile.parent_path()/L"desktop-settings.json";if(std::filesystem::exists(profile))value=readFile(profile);if(std::filesystem::exists(desktopPath))desktop=Json::parse(readFile(desktopPath));}catch(const std::exception& e){note(std::string("Не удалось загрузить настройки: ")+e.what());}
        if(!desktop.is_object())desktop=Json::object();
        auto settings=desktop.value("ssh",Json::object());if(!settings.is_object())settings=Json::object();auto setSetting=[&](int id,const char* key,const Json& fallback){auto field=settings.value(key,fallback);setText(GetDlgItem(window,id),field.is_string()?field.get<std::string>():field.is_null()?std::string():field.dump());};
        setSetting(SshHost,"host","");setSetting(SshPort,"port",22);setSetting(SshUser,"user","");setSetting(KeyPath,"identity_file",nullptr);setSetting(KnownHosts,"known_hosts_file",nullptr);setSetting(SshExecutable,"ssh_executable",nullptr);setSetting(LocalPort,"local_port",1080);setSetting(Keepalive,"server_alive_interval_secs",15);setSetting(KeepaliveCount,"server_alive_count_max",3);setSetting(RetryInitial,"restart_initial_delay_ms",1000);setSetting(RetryMax,"restart_max_delay_ms",30000);SendMessageW(GetDlgItem(window,Compression),BM_SETCHECK,settings.value("compression",false)?BST_CHECKED:BST_UNCHECKED,0);
        const auto savedCount=desktop.value("ssh_workers",Json(1));
        const int sshWorkerCount=savedCount.is_number_integer()?std::clamp(savedCount.get<int>(),1,4):1;
        SendMessageW(GetDlgItem(window,SshPoolWorkers),CB_SETCURSEL,sshWorkerCount-1,0);
        // Existing desktop profiles migrate to checked-by-default behavior.
        const auto savedRemoteDns=desktop.value("remote_dns_via_ssh",Json(true));
        const bool remoteDnsEnabled=savedRemoteDns.is_boolean()?savedRemoteDns.get<bool>():true;
        SendMessageW(GetDlgItem(window,RemoteDns),BM_SETCHECK,remoteDnsEnabled?BST_CHECKED:BST_UNCHECKED,0);
        if(!savedRemoteDns.is_boolean())note("Некорректная настройка DNS: включён безопасный режим по умолчанию.");
        SendMessageW(mode,CB_SETCURSEL,desktop.value("managed_ssh",false)?1:0,0);SendMessageW(GetDlgItem(window,BlockOthers),BM_SETCHECK,desktop.value("block_other_applications",false)?BST_CHECKED:BST_UNCHECKED,0);selectedPreset=desktop.value("preset",std::string("ai_web"));for(const auto& selected:desktop.value("selected_applications",std::vector<std::string>{}))selectedApps.insert(selected);dark=desktop.value("dark",false);
        try{wchar_t exe[32768]{};GetModuleFileNameW(nullptr,exe,32768);auto resource=std::filesystem::path(exe).parent_path()/L"resources"/L"presets.json";if(!std::filesystem::exists(resource))resource=std::filesystem::path(__FILE__).parent_path().parent_path().parent_path()/"resources"/"presets.json";catalog=Json::parse(readFile(resource));}catch(const std::exception& e){catalog=Json::object();note(std::string("Каталог шаблонов недоступен: ")+e.what());}
        setText(configEdit,value);fillQuick();applyTheme();switchPage(0);worker.start();SetTimer(h,1,1000,nullptr);return 0;
    }
    case WM_SIZE: layout(); return 0;
    case WM_GETMINMAXINFO: reinterpret_cast<MINMAXINFO*>(l)->ptMinTrackSize={980,680}; return 0;
    case WM_COMMAND:
        try {
            int id=LOWORD(w),event=HIWORD(w);
            if((id==Host||id==Port)&&event==EN_CHANGE&&!filling)quickDirty=true;
            if(id==Protocol&&event==CBN_SELCHANGE&&!filling)quickDirty=true;
            if(id==Proxy&&event==CBN_SELCHANGE)selectedProxy();
            if(id==ManagedMode&&event==CBN_SELCHANGE){updateVisibility();layout();enableControls();InvalidateRect(h,nullptr,TRUE);}
            if(event==BN_CLICKED&&!closing){
                if(id>=NavDashboard&&id<=NavAdvanced)switchPage(id-NavDashboard);
                else if(id==Theme){dark=!dark;applyTheme();try{saveDesktop();}catch(const std::exception& e){note(e.what());}}
                else if(id==ExportDiagnostics){exportDiagnostics();}
                else if(id==RemoteDns&&!busy){
                    saveDesktop();
                    note("DNS через SSH: только hostname в явном SOCKS5. Без галочки доступны лишь IP; локального DNS fallback нет. Для новых соединений примените профиль. Прозрачный DNS WFP не защищён.");
                }
                else if(id==SaveDesktop&&!busy){
                    // Pure desktop preferences are saved synchronously. No
                    // worker dispatch, SSH connection, or engine apply occurs.
                    // This is the same trusted path as Theme and Remote DNS.
                    saveDesktop();
                    note("Параметры подключения сохранены. Активный SSH не меняется до переподключения.");
                }
                else if(!busy){
                    if(id==Start||id==Apply){
                         if(nativeCapture.active()||nativeCapture.stopping())
                             throw std::runtime_error("Сначала остановите нативный перехват, затем меняйте или останавливайте SSH.");
                         workerError.clear();auto value=commandConfiguration();auto settings=desktopSettings();validateDesktop(settings);if(settings.value("managed_ssh",false))validateManagedRoute(value,settings["ssh"],settings.value("ssh_workers",1));dispatch(id,std::move(value),std::move(settings));}
                    else if(id==Stop){
                         if(nativeCapture.active()||nativeCapture.stopping())
                             stopNativeCapture(); // first remove WFP filters, then user can stop SSH
                         else {workerError.clear();dispatch(Stop);}
                     }
                    else if(id==VisualRules){
                         // One modal draft transaction; no background SSH/engine changes.
                         // The established Apply path remains the only route activation.
                         if(nativeCapture.active()||nativeCapture.stopping())
                             throw std::runtime_error("Сначала остановите WFP-перехват, чтобы безопасно менять правила.");
                         auto edited=rule_editor::run(window,configuration());
                         if(edited){
                             setText(configEdit,*edited);
                             // The native EDIT control must contain all the validated
                             // JSON. Fail rather than silently truncating a profile.
                             if(Json::parse(utf8(configEdit))!=Json::parse(*edited))
                                 throw std::runtime_error("Редактор Windows не сохранил весь JSON; проверьте размер профиля.");
                             fillQuick();
                             note("Черновик правил проверен Rust; нажмите «Применить профиль» для изменения маршрута.");
                         }
                     }
                    else if(id==Open||id==Save)fileDialog(id==Save);
                    else if(id==BrowseKey||id==BrowseKnown||id==BrowseSsh){
                         auto path=chooseFile(id==BrowseSsh?L"OpenSSH exe\0*.exe\0":L"Все файлы\0*.*\0",false,id==BrowseSsh?L"exe":L"");
                         if(!path.empty())setText(GetDlgItem(h,id==BrowseKey?KeyPath:id==BrowseKnown?KnownHosts:SshExecutable),discovery::utf8(path.wstring()));
                     }
                    else if(id==Discover){captureSelections();setText(GetDlgItem(h,ScanStatus),"Ищем приложения локально… Сканирование ограничено по времени и объёму.");dispatch(DiscoverCommand,{},catalog);}
                    else if(id==PresetAI||id==PresetWeb||id==PresetBoth)choosePreset(id==PresetAI?"ai":id==PresetWeb?"web":"ai_web");
                    else if(id==BrowseApp)browseApplication();
                    else if(id==ExportNative)exportProxiFyre();
                    else if(id==StartCapture)startNativeCapture();
                    else if(id==StopCapture)stopNativeCapture();
                    else if(id==BlockOthers)saveDesktop();
                }
            }
        }catch(const std::exception& e){note(std::string("Ошибка: ")+e.what());}
        return 0;
    case WM_NOTIFY:{auto notification=reinterpret_cast<NMHDR*>(l);if(notification->idFrom==AppsTable&&notification->code==LVN_ITEMCHANGED&&!loadingApps&&((reinterpret_cast<NMLISTVIEW*>(l)->uOldState^reinterpret_cast<NMLISTVIEW*>(l)->uNewState)&LVIS_STATEIMAGEMASK)){captureSelections();setText(GetDlgItem(h,AppsSummary),"Найдено: "+std::to_string(discovered.size())+"   •   Выбрано: "+std::to_string(selectedApps.size())+"   •   Эвристика; проверяйте путь EXE");try{saveDesktop();}catch(const std::exception& e){note(e.what());}}return 0;}
    case WM_TIMER: {
        DWORD exitCode=0;
        if(nativeCapture.poll(exitCode)) {
            setText(GetDlgItem(h,CaptureStatus),"Нативный helper завершился. Код: "+std::to_string(exitCode)+". Открытые соединения прерваны.");
            note(exitCode==0?"Нативный перехват остановлен.":"Нативный helper завершился с ошибкой: "+std::to_string(exitCode)+". Проверьте WFP-драйвер и журнал helper.");
            enableControls();
        }
        if(closing)finishCloseAfterCapture();
        else if(!busy)dispatch(PollCommand);
        return 0;
    }
    case Completed: {
        std::unique_ptr<Result> result(reinterpret_cast<Result*>(l)); busy=false;pendingStart=result->waiting;
        if(result->exit) { DestroyWindow(h); return 0; }
        if(closing) { finishCloseAfterCapture(); return 0; }
        try {
            if(!result->acceptedDesktop.is_null()&&!desktopPath.empty()){writeFile(desktopPath,result->acceptedDesktop.dump(2));desktop=result->acceptedDesktop;}
            if(!result->saved.empty()) {
                if(profile.empty()) throw std::runtime_error("No profile directory available; use Export JSON to keep settings.");
                writeFile(profile,result->saved); fillQuick(); note("Настройки сохранены.");
            }
            if(!result->error.empty()) { workerError=result->error; note("Ошибка: "+result->error); }
            if(result->scanned){
                discoveryDone=true;auto prior=selectedApps;discovered=std::move(result->apps);
                for(const auto& path:prior){auto file=std::filesystem::path(wide(path));std::error_code ec;bool exists=file.is_absolute()&&file.wstring().size()>2&&file.wstring()[1]==L':'&&std::filesystem::is_regular_file(file,ec);auto found=std::find_if(discovered.begin(),discovered.end(),[&](const discovery::App& app){return app.path==path;});if(exists&&found==discovered.end())discovered.push_back({"manual",discovery::utf8(file.stem().wstring()),path,"Сохранённый выбор",100});}
                if(prior.empty()){choosePreset(selectedPreset);}else{selectedApps.clear();for(const auto& app:discovered)if(prior.count(app.path))selectedApps.insert(app.path);refreshApps();}
                setText(GetDlgItem(h,ScanStatus),"Поиск завершён. Это предложения по локальным признакам, без проверки подписи издателя.");
            }else{showSnapshot(result->snapshot);showSsh(result->ssh,result->waiting);}
        } catch(const std::exception& e) { note(std::string("Ошибка: ")+e.what()); }
        enableControls(); return 0;
    }
    case WM_CLOSE:
        if(!closing) {
            nativeCapture.stop();
            try{captureSelections();saveDesktop();}catch(const std::exception& e){note(e.what());}
            closing=true;
            setText(GetDlgItem(h,Status),
                    nativeCapture.active()||nativeCapture.stopping()
                    ?"Ожидаем снятия WFP-фильтров перед остановкой пользовательского SSH…"
                    :"Останавливаем движок и SSH…");
            enableControls();
            finishCloseAfterCapture();
        }
        return 0;
    case WM_ERASEBKGND:return 1;
    case WM_PAINT:{PAINTSTRUCT ps{};HDC dc=BeginPaint(h,&ps);RECT r{};GetClientRect(h,&r);FillRect(dc,&r,backgroundBrush);RECT side{0,0,212,r.bottom};FillRect(dc,&side,sidebarBrush);
        SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(237,243,255));SelectObject(dc,headingFont);RECT brand{27,36,197,70};DrawTextW(dc,L"FlowBridge",-1,&brand,DT_LEFT|DT_SINGLELINE);SelectObject(dc,smallFont);SetTextColor(dc,RGB(143,164,195));RECT tag{28,79,194,117};DrawTextW(dc,L"ЛИЧНЫЙ МАРШРУТ\nSSH / SOCKS5",-1,&tag,DT_LEFT);RECT version{28,r.bottom-203,195,r.bottom-158};DrawTextW(dc,L"v0.2.0\nЛокальный режим",-1,&version,DT_LEFT);
        auto panel=[&](int top,int bottom){HPEN pen=CreatePen(PS_SOLID,1,dark?RGB(45,61,83):RGB(225,232,242));auto oldPen=SelectObject(dc,pen);auto oldBrush=SelectObject(dc,cardBrush);RoundRect(dc,236,top,r.right-28,bottom,18,18);SelectObject(dc,oldPen);SelectObject(dc,oldBrush);DeleteObject(pen);};
        if(activePage==0){panel(132,266);panel(274,308);panel(313,400);}else if(activePage==1){panel(124,208);bool managed=SendMessageW(GetDlgItem(h,ManagedMode),CB_GETCURSEL,0,0)==1;panel(212,managed?586:435);}else if(activePage==2)panel(124,201);
        EndPaint(h,&ps);return 0;}
    case WM_CTLCOLORSTATIC:case WM_CTLCOLOREDIT:case WM_CTLCOLORLISTBOX:case WM_CTLCOLORBTN:{HDC dc=reinterpret_cast<HDC>(w);HWND child=reinterpret_cast<HWND>(l);int id=GetDlgCtrlID(child);bool plain=id==Banner||id==PageTitle||id==PageSubtitle||id==ConfigLabel||id==ConnectionsLabel||id==LogLabel||id==DashboardHelp||id==ScanStatus||id==AppsSummary||id==2018;
        SetTextColor(dc,id==Badge?(engineRunning&&tunnelReady?RGB(18,143,98):engineRunning?RGB(180,120,23):muted()):(id==PageSubtitle||id==Mode||id==SshHelp||id==AppsHelp||id==ScanStatus||id==2018?muted():ink()));SetBkColor(dc,plain?bg():card());return reinterpret_cast<LRESULT>(plain?backgroundBrush:cardBrush);}
    case WM_DRAWITEM:{auto item=reinterpret_cast<DRAWITEMSTRUCT*>(l);if(item->CtlType!=ODT_BUTTON)break;int id=static_cast<int>(item->CtlID);bool nav=id>=NavDashboard&&id<=NavAdvanced;bool selected=(nav&&id-NavDashboard==activePage)||(id==PresetAI&&selectedPreset=="ai")||(id==PresetWeb&&selectedPreset=="web")||(id==PresetBoth&&selectedPreset=="ai_web");bool primary=id==Start||id==StartCapture||id==ExportNative||id==SaveDesktop;bool enabled=(item->itemState&ODS_DISABLED)==0;bool down=(item->itemState&ODS_SELECTED)!=0;
        COLORREF fill=nav?(selected?RGB(43,63,92):RGB(18,30,52)):primary?(enabled?RGB(45,105,231):RGB(134,159,201)):selected?(dark?RGB(37,68,112):RGB(227,238,255)):card();if(down)fill=RGB(48,87,150);
        HBRUSH brush=CreateSolidBrush(fill);HPEN pen=CreatePen(PS_SOLID,1,nav?fill:primary?fill:(dark?RGB(64,82,107):RGB(215,224,237)));auto oldB=SelectObject(item->hDC,brush);auto oldP=SelectObject(item->hDC,pen);RECT box=item->rcItem;FillRect(item->hDC,&box,nav||id==Theme?sidebarBrush:(id==BrowseKey||id==BrowseKnown?cardBrush:backgroundBrush));RoundRect(item->hDC,box.left,box.top,box.right,box.bottom,10,10);SelectObject(item->hDC,oldB);SelectObject(item->hDC,oldP);DeleteObject(brush);DeleteObject(pen);
        SetBkMode(item->hDC,TRANSPARENT);SetTextColor(item->hDC,!enabled?(primary?RGB(235,242,254):muted()):nav||primary?RGB(244,248,255):selected?RGB(54,112,220):ink());SelectObject(item->hDC,bodyFont);auto text=utf8(item->hwndItem);auto label=wide(text);RECT textBox=box;if(nav)textBox.left+=16;DrawTextW(item->hDC,label.c_str(),-1,&textBox,(nav?DT_LEFT:DT_CENTER)|DT_VCENTER|DT_SINGLELINE);if(item->itemState&ODS_FOCUS){InflateRect(&box,-4,-4);DrawFocusRect(item->hDC,&box);}return TRUE;}
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h,message,w,l);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show) {
    // Shared with installer: an existing process must exit before replacement or uninstall.
    HANDLE guard=CreateMutexW(nullptr,FALSE,L"Local\\FlowBridge.NativeUI.v02");
    if(!guard || GetLastError()==ERROR_ALREADY_EXISTS) { if(guard) CloseHandle(guard); MessageBoxW(nullptr,L"FlowBridge is already running in this session.",L"FlowBridge",MB_OK|MB_ICONINFORMATION); return 1; }
    INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&controls);
    SetProcessDPIAware();
    bodyFont=CreateFontW(-16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    titleFont=CreateFontW(-28,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    headingFont=CreateFontW(-21,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    smallFont=CreateFontW(-13,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    WNDCLASSW cls{}; cls.lpfnWndProc=windowProc; cls.hInstance=instance; cls.lpszClassName=L"FlowBridgeNativeV02"; cls.hCursor=LoadCursorW(nullptr,IDC_ARROW); cls.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
    if(!RegisterClassW(&cls)) { CloseHandle(guard); return 1; }
    RECT workArea{};SystemParametersInfoW(SPI_GETWORKAREA,0,&workArea,0);
    const int availableW=workArea.right-workArea.left,availableH=workArea.bottom-workArea.top;
    const int initialW=std::min(1180,std::max(980,availableW));
    const int initialH=std::min(760,std::max(680,availableH));
    HWND h=CreateWindowW(cls.lpszClassName,L"FlowBridge 0.2 — личный маршрут",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
                         workArea.left,workArea.top,initialW,initialH,nullptr,nullptr,instance,nullptr);
    if(!h) { CloseHandle(guard); return 1; } ShowWindow(h,show); MSG msg{}; BOOL status;
    while((status=GetMessageW(&msg,nullptr,0,0))>0) { if(!IsDialogMessageW(h,&msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); } }
    CloseHandle(guard); return status==-1?1:static_cast<int>(msg.wParam);
}
