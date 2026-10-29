#pragma once
#include <windows.h>
#include <shellapi.h>
#include <objbase.h>
#include <filesystem>
#include <string>
#include <vector>
#include <stdexcept>

// Unprivileged GUI owns the stop event and observes an elevated helper.
// The helper also watches the GUI PID, so abnormal GUI exit removes dynamic
// WFP filters instead of leaving a privileged proxy running unattended.
namespace capture_launcher {
inline std::wstring quote(const std::wstring& input) {
    if (input.empty() || input.find(L'\0') != std::wstring::npos ||
        input.find(L'\r') != std::wstring::npos || input.find(L'\n') != std::wstring::npos)
        throw std::runtime_error("Invalid native-capture argument");
    std::wstring output=L"\"";
    unsigned backslashes=0;
    for (wchar_t character:input) {
        if (character==L'\\') {++backslashes;continue;}
        if (character==L'\"') {
            output.append(backslashes*2+1,L'\\'); output.push_back(L'\"');
        } else {output.append(backslashes,L'\\');output.push_back(character);}
        backslashes=0;
    }
    output.append(backslashes*2,L'\\');output.push_back(L'\"');
    return output;
}
inline std::wstring arguments(const std::wstring& profile,
                             const std::wstring& ssh,
                             const std::vector<std::wstring>& apps,
                             DWORD owner, const std::wstring& eventName,
                             const std::vector<std::wstring>& bypass={}) {
    if (!owner || apps.empty() || apps.size()>64 || bypass.size()>16 ||
        !std::filesystem::path(profile).is_absolute())
        throw std::runtime_error("Native capture requires an owner, profile, and 1..64 EXE paths");
    if(!ssh.empty() && !std::filesystem::path(ssh).is_absolute())
        throw std::runtime_error("SSH profile must be absolute");
    if(eventName.rfind(L"Local\\FlowBridgeCaptureStop-",0)!=0 || eventName.size()>128)
        throw std::runtime_error("Native capture stop event is invalid");
    std::wstring command=L"--console --profile "+quote(profile)+L" --gui-owner "+std::to_wstring(owner)+
                         L" --stop-event "+quote(eventName);
    if(!ssh.empty())command+=L" --ssh-profile "+quote(ssh);
    for(const auto& path:apps) {
        if(!std::filesystem::path(path).is_absolute() ||
           !std::filesystem::is_regular_file(path))
            throw std::runtime_error("Select existing absolute executable paths");
        command+=L" --capture-app "+quote(path);
    }
    // The GUI/SSH executable must never be selected for redirect by mistake:
    // the observed path of the actual OpenSSH backend is exempt at WFP ALE.
    for(const auto& path:bypass) {
        if(!std::filesystem::path(path).is_absolute() ||
           !std::filesystem::is_regular_file(path))
            throw std::runtime_error("Bypass executable must be an existing absolute path");
        for(const auto& selected:apps) {
            std::error_code ec;
            if(std::filesystem::equivalent(std::filesystem::path(path),
                                           std::filesystem::path(selected),ec))
                throw std::runtime_error("Selected executable is the GUI/SSH bypass executable; deselect it");
        }
        command+=L" --bypass "+quote(path);
    }
    return command;
}
class Session {
    HANDLE process_=nullptr;
    HANDLE stop_=nullptr;
    bool stopRequested_=false;
public:
    Session()=default;
    Session(const Session&)=delete; Session& operator=(const Session&)=delete;
    ~Session(){stop();reset();}
    void reset() noexcept {
        if(process_){CloseHandle(process_);process_=nullptr;}
        if(stop_){CloseHandle(stop_);stop_=nullptr;}
        stopRequested_=false;
    }
    bool active() const noexcept {return process_&&WaitForSingleObject(process_,0)==WAIT_TIMEOUT;}
    bool stopping() const noexcept {return stopRequested_;}
    bool poll(DWORD& exitCode) noexcept {
        if(!process_||WaitForSingleObject(process_,0)!=WAIT_OBJECT_0)return false;
        exitCode=1;GetExitCodeProcess(process_,&exitCode);reset();return true;
    }
    void stop() noexcept {if(stop_){SetEvent(stop_);stopRequested_=true;}}
    void start(const std::wstring& profile,const std::wstring& ssh,
               const std::vector<std::wstring>& apps,
               const std::vector<std::wstring>& bypass={}) {
        if(process_)throw std::runtime_error("Native capture is already active or stopping");
        wchar_t module[32768]{};
        DWORD n=GetModuleFileNameW(nullptr,module,32768);
        if(!n||n>=32768)throw std::runtime_error("Unable to locate FlowBridge executable");
        auto helper=std::filesystem::path(module).parent_path()/L"FlowBridgeCapture.exe";
        if(!std::filesystem::is_regular_file(helper))
            throw std::runtime_error("FlowBridgeCapture.exe is not installed; install a native beta package");
        GUID guid{};
        if(FAILED(CoCreateGuid(&guid)))throw std::runtime_error("Unable to create capture session identifier");
        wchar_t id[48]{};StringFromGUID2(guid,id,48);
        std::wstring name=L"Local\\FlowBridgeCaptureStop-"+std::wstring(id);
        HANDLE control=CreateEventW(nullptr,TRUE,FALSE,name.c_str());
        if(!control||GetLastError()==ERROR_ALREADY_EXISTS){if(control)CloseHandle(control);throw std::runtime_error("Capture event creation failed");}
        try {
            auto params=arguments(profile,ssh,apps,GetCurrentProcessId(),name,bypass);
            SHELLEXECUTEINFOW launch{};
            launch.cbSize=sizeof(launch);
            launch.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_FLAG_NO_UI;
            launch.lpVerb=L"runas";launch.lpFile=helper.c_str();
            launch.lpParameters=params.c_str();launch.nShow=SW_SHOWMINNOACTIVE;
            if(!ShellExecuteExW(&launch)||!launch.hProcess) {
                auto code=GetLastError();
                throw std::runtime_error(code==ERROR_CANCELLED?
                    "UAC elevation was cancelled":"Unable to start privileged capture helper: "+std::to_string(code));
            }
            process_=launch.hProcess;stop_=control;stopRequested_=false;
        }catch(...){CloseHandle(control);throw;}
    }
};
}
