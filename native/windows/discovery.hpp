#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <filesystem>
#include <chrono>
#include <vector>
#include <set>
#include <string>
#include <algorithm>
#include <cwctype>
#include "nlohmann/json.hpp"
namespace discovery {
using Json=nlohmann::json;
struct App { std::string id,name,path,source; int confidence=0; };
inline std::wstring lower(std::wstring s) { std::transform(s.begin(),s.end(),s.begin(),[](wchar_t c){return static_cast<wchar_t>(std::towlower(c));}); return s; }
inline std::wstring wide(const std::string& s) { int n=MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0); std::wstring out(n,0); if(n) MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),out.data(),n); return out; }
inline std::string utf8(const std::wstring& s) { int n=WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr); std::string out(n,0); if(n) WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr); return out; }
inline std::wstring registryString(HKEY key,const wchar_t* name) { DWORD type=0,bytes=0; if(RegQueryValueExW(key,name,nullptr,&type,nullptr,&bytes)!=ERROR_SUCCESS || (type!=REG_SZ&&type!=REG_EXPAND_SZ) || bytes>65536) return {}; std::wstring value(bytes/sizeof(wchar_t)+1,0); if(RegQueryValueExW(key,name,nullptr,&type,reinterpret_cast<BYTE*>(value.data()),&bytes)!=ERROR_SUCCESS)return {}; value.resize(wcsnlen(value.c_str(),value.size())); if(type==REG_EXPAND_SZ) { wchar_t expanded[32768]{}; DWORD n=ExpandEnvironmentStringsW(value.c_str(),expanded,32768); if(n&&n<=32768)value=expanded; } return value; }
inline std::wstring iconPath(std::wstring value) { if(value.empty()) return {}; if(value[0]==L'"') { auto end=value.find(L'"',1); return end==std::wstring::npos?L"":value.substr(1,end-1); } auto comma=value.rfind(L','); if(comma!=std::wstring::npos)value.resize(comma); return value; }
inline std::vector<App> scan(const Json& catalog) {
    std::vector<App> out; std::set<std::wstring> paths; auto until=std::chrono::steady_clock::now()+std::chrono::seconds(6);
    auto expired=[&]{return std::chrono::steady_clock::now()>until || out.size()>=256;};
    auto add=[&](const std::wstring& path,const std::string& source,const std::wstring& hint=L"") {
        if(expired() || path.size()<4 || path[1]!=L':' || path[2]!=L'\\') return; // never inspect UNC/network paths
        wchar_t drive[]={path[0],L':',L'\\',0};if(GetDriveTypeW(drive)==DRIVE_REMOTE)return;
        std::error_code ec; auto candidate=std::filesystem::path(path); if(!std::filesystem::is_regular_file(candidate,ec))return;
        auto normalized=lower(candidate.lexically_normal().wstring()); if(paths.count(normalized))return;
        auto exe=lower(candidate.filename().wstring());
        for(const auto& app:catalog.value("apps",Json::array())) {
            bool exact=false, named=false;
            for(const auto& name:app.value("windows_executables",std::vector<std::string>{})) if(exe==lower(wide(name)))exact=true;
            if(!hint.empty())for(const auto& name:app.value("windows_name_hints",std::vector<std::string>{})) if(lower(hint).find(lower(wide(name)))!=std::wstring::npos)named=true;
            if(exact || named) { paths.insert(normalized); out.push_back({app.value("id",std::string()),app.value("name",std::string()),utf8(candidate.wstring()),source,exact?90:60}); return; }
        }
    };
    const wchar_t* branches[]={L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"};
    for(auto hive:{HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE}) for(auto view:{KEY_WOW64_64KEY,KEY_WOW64_32KEY}) for(int branch=0;branch<2&&!expired();++branch) {
        HKEY root=nullptr; if(RegOpenKeyExW(hive,branches[branch],0,KEY_READ|view,&root)!=ERROR_SUCCESS)continue;
        for(DWORD index=0;index<1500&&!expired();++index) { wchar_t child[512]{}; DWORD size=512; if(RegEnumKeyExW(root,index,child,&size,nullptr,nullptr,nullptr,nullptr)!=ERROR_SUCCESS)break;
            HKEY key=nullptr; if(RegOpenKeyExW(root,child,0,KEY_READ|view,&key)!=ERROR_SUCCESS)continue;
            if(branch==0)add(iconPath(registryString(key,nullptr)),"App Paths");
            else { auto label=registryString(key,L"DisplayName"); add(iconPath(registryString(key,L"DisplayIcon")),"Installed registry",label);
                auto location=registryString(key,L"InstallLocation"); if(!location.empty()) for(const auto& app:catalog.value("apps",Json::array())) {
                    bool matches=false; for(const auto& hint:app.value("windows_name_hints",std::vector<std::string>{}))if(lower(label).find(lower(wide(hint)))!=std::wstring::npos)matches=true;
                    if(matches) for(const auto& exe:app.value("windows_executables",std::vector<std::string>{})) add((std::filesystem::path(location)/wide(exe)).wstring(),"InstallLocation",label);
                }
            } RegCloseKey(key);
        } RegCloseKey(root);
    }
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot!=INVALID_HANDLE_VALUE) { PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);DWORD count=0;
        for(BOOL ok=Process32FirstW(snapshot,&entry);ok&&count<1500&&!expired();ok=Process32NextW(snapshot,&entry),++count) { HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);if(!process)continue; wchar_t path[32768]{};DWORD size=32768;if(QueryFullProcessImageNameW(process,0,path,&size))add(path,"Running process");CloseHandle(process); } CloseHandle(snapshot);
    }
    HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(SUCCEEDED(init)) {
        for(const auto* folder:{&FOLDERID_Programs,&FOLDERID_CommonPrograms}) { PWSTR path=nullptr;if(FAILED(SHGetKnownFolderPath(*folder,0,nullptr,&path)))continue;std::filesystem::path base(path);CoTaskMemFree(path);if(base.wstring().size()<3||base.wstring()[1]!=L':')continue;std::error_code ec;size_t count=0;
            for(std::filesystem::recursive_directory_iterator it(base,std::filesystem::directory_options::skip_permission_denied,ec),end;it!=end&&!ec&&!expired()&&count<1200;it.increment(ec),++count) {
                if(it.depth()>=3)it.disable_recursion_pending();
                DWORD attributes=GetFileAttributesW(it->path().c_str());if(attributes!=INVALID_FILE_ATTRIBUTES&&(attributes&FILE_ATTRIBUTE_REPARSE_POINT)){it.disable_recursion_pending();continue;}
                if(lower(it->path().extension().wstring())!=L".lnk")continue;
                auto label=lower(it->path().stem().wstring());bool known=false;for(const auto& app:catalog.value("apps",Json::array()))for(const auto& hint:app.value("windows_name_hints",std::vector<std::string>{}))if(label.find(lower(wide(hint)))!=std::wstring::npos)known=true;
                if(!known)continue;
                IShellLinkW* link=nullptr;if(FAILED(CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,reinterpret_cast<void**>(&link))))continue;
                IPersistFile* file=nullptr;if(SUCCEEDED(link->QueryInterface(IID_IPersistFile,reinterpret_cast<void**>(&file)))) { if(SUCCEEDED(file->Load(it->path().c_str(),STGM_READ))) { wchar_t target[32768]{};if(SUCCEEDED(link->GetPath(target,32768,nullptr,SLGP_RAWPATH)))add(target,"Start Menu shortcut",label); }file->Release(); }link->Release();
            }
        }CoUninitialize();
    }
    std::sort(out.begin(),out.end(),[](const App& a,const App& b){return a.name<b.name || (a.name==b.name&&a.path<b.path);});return out;
}
}
