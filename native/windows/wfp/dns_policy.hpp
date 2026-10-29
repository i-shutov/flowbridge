#pragma once
#include "../native_ipc.hpp"
#include <windows.h>
#include <filesystem>
#include <stdexcept>
#include <string>

// Only a fixed, installed script is elevated. No user-supplied shell commands.
// Destruction is a final best-effort rollback; normal Stop calls restore() and
// must surface failure instead of reporting that DNS has been restored.
class DnsPolicy {
    std::wstring token_=native_ipc::guid();
    bool active_=false;
    void invoke(const wchar_t* action) {
        wchar_t windows[32768]{};UINT n=GetWindowsDirectoryW(windows,32768);
        if(!n||n>=32768)throw std::runtime_error("Windows directory unavailable");
        auto powershell=std::filesystem::path(windows)/L"System32"/L"WindowsPowerShell"/L"v1.0"/L"powershell.exe";
        auto script=native_ipc::executableDirectory()/L"dns_policy.ps1";
        if(!std::filesystem::is_regular_file(script))throw std::runtime_error("Installed DNS rollback script is missing");
        std::wstring command=native_ipc::quote(powershell.wstring())+L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "+
            native_ipc::quote(script.wstring())+L" -Action "+action+L" -Token "+token_+L" -OwnerProcessId "+std::to_wstring(GetCurrentProcessId());
        STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
        if(!CreateProcessW(powershell.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process))
            throw std::runtime_error("Cannot run DNS transaction: "+std::to_string(GetLastError()));
        CloseHandle(process.hThread);
        auto wait=WaitForSingleObject(process.hProcess,20000);
        if(wait!=WAIT_OBJECT_0){TerminateProcess(process.hProcess,1);WaitForSingleObject(process.hProcess,5000);CloseHandle(process.hProcess);throw std::runtime_error("DNS transaction deadline expired; rollback required");}
        DWORD code=1;GetExitCodeProcess(process.hProcess,&code);CloseHandle(process.hProcess);
        if(code)throw std::runtime_error("Windows DNS transaction failed ("+std::to_string(code)+"). Existing NRPT policy, port 53 ownership, or permissions may conflict.");
    }
public:
    ~DnsPolicy(){if(active_){try{restore();}catch(...){OutputDebugStringA("FlowBridge DNS rollback not confirmed; guardian recovery remains required\n");}}}
    void enter(){if(active_)throw std::runtime_error("DNS already enabled");invoke(L"Recover");active_=true;invoke(L"Enter");}
    void restore(){if(active_){invoke(L"Exit");active_=false;}}
    bool active()const{return active_;}
};
