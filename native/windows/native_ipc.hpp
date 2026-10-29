#pragma once
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <filesystem>
#include <fstream>
#include <array>
#include <stdexcept>
#include <string>
#include <utility>
#include "nlohmann/json.hpp"

namespace native_ipc {
using Json=nlohmann::json;
constexpr DWORD MaxMessage=65536;
inline std::wstring wide(const std::string& s) {
    if(s.empty())return {};
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(!n)throw std::runtime_error("Invalid UTF-8 IPC value");
    std::wstring out(n,0);MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n);return out;
}
inline std::wstring quote(const std::wstring& value) {
    if(value.find_first_of(L"\r\n\0",0,3)!=std::wstring::npos)throw std::runtime_error("Invalid process argument");
    std::wstring out=L"\"";size_t slashes=0;
    for(wchar_t c:value){if(c==L'\\'){++slashes;continue;}out.append(c==L'\"'?slashes*2+1:slashes,L'\\');slashes=0;out+=c;}
    out.append(slashes*2,L'\\');return out+L"\"";
}
inline std::filesystem::path executableDirectory() {
    wchar_t buffer[32768]{};DWORD n=GetModuleFileNameW(nullptr,buffer,32768);
    if(!n||n>=32768)throw std::runtime_error("Executable path unavailable");
    return std::filesystem::path(std::wstring(buffer,n)).parent_path();
}
inline std::wstring guid() {
    GUID id{};if(FAILED(CoCreateGuid(&id)))throw std::runtime_error("Cannot create capture token");
    wchar_t text[40]{};StringFromGUID2(id,text,40);return std::wstring(text+1,36);
}
inline std::wstring pipeName(const std::wstring& token) {
    if(token.size()!=36||token.find_first_not_of(L"0123456789abcdefABCDEF-")!=std::wstring::npos)throw std::runtime_error("Invalid capture token");
    return L"\\\\.\\pipe\\FlowBridge.Capture."+token;
}
inline bool send(HANDLE pipe,const Json& value) {
    auto text=value.dump();if(text.size()>MaxMessage)throw std::runtime_error("IPC message too large");
    DWORD sent=0;return WriteFile(pipe,text.data(),static_cast<DWORD>(text.size()),&sent,nullptr)&&sent==text.size();
}
inline bool receive(HANDLE pipe,Json& value) {
    DWORD available=0;
    if(!PeekNamedPipe(pipe,nullptr,0,nullptr,&available,nullptr)) {
        auto error=GetLastError();if(error==ERROR_PIPE_LISTENING||error==ERROR_PIPE_NOT_CONNECTED)return false;
        throw std::runtime_error("Native control pipe disconnected");
    }
    if(!available)return false;
    std::array<char,MaxMessage> buffer{};DWORD read=0;
    if(!ReadFile(pipe,buffer.data(),static_cast<DWORD>(buffer.size()),&read,nullptr)||!read)throw std::runtime_error("Invalid native IPC message");
    value=Json::parse(buffer.data(),buffer.data()+read);if(!value.is_object())throw std::runtime_error("Expected IPC object");return true;
}
inline void close(HANDLE& handle) {if(handle&&handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);handle=nullptr;}

// Child endpoint: no elevated status writes to user-controlled paths. Both ends
// verify the actual process identity associated with the kernel pipe object.
class Child {
    HANDLE pipe_=nullptr,parent_=nullptr;
public:
    ~Child(){close(pipe_);close(parent_);}
    bool attached()const{return pipe_!=nullptr;}
    void attach(const std::wstring& token,DWORD owner) {
        if(!owner)throw std::runtime_error("Missing UI owner");
        parent_=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,owner);
        if(!parent_)throw std::runtime_error("UI owner is unavailable");
        auto name=pipeName(token);
        pipe_=CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
        if(pipe_==INVALID_HANDLE_VALUE){pipe_=nullptr;throw std::runtime_error("Cannot attach native control pipe");}
        ULONG actual=0;
        if(!GetNamedPipeServerProcessId(pipe_,&actual)||actual!=owner)throw std::runtime_error("Native control pipe owner mismatch");
        DWORD mode=PIPE_READMODE_MESSAGE|PIPE_NOWAIT;
        if(!SetNamedPipeHandleState(pipe_,&mode,nullptr,nullptr))throw std::runtime_error("Cannot configure native pipe");
    }
    bool alive()const{return !parent_||WaitForSingleObject(parent_,0)==WAIT_TIMEOUT;}
    bool read(Json& value){return pipe_&&receive(pipe_,value);}
    void status(const Json& value)noexcept{try{if(pipe_)send(pipe_,value);}catch(...) {}}
};

// Called on the GUI worker thread. SSH and private-key access stay unelevated.
class Parent {
    HANDLE pipe_=nullptr,process_=nullptr;
    std::filesystem::path directory_;
    Json last_=Json::object();ULONGLONG started_=0,observed_=0;
    void write(const wchar_t* name,const Json& value){
        std::ofstream out(directory_/name,std::ios::binary|std::ios::trunc);auto data=value.dump();
        out.write(data.data(),static_cast<std::streamsize>(data.size()));out.close();
        if(!out)throw std::runtime_error("Cannot save native session input");
    }
    void cleanup()noexcept {
        close(process_);close(pipe_);
        std::error_code error;
        for(auto name:{L"profile.json",L"options.json"})std::filesystem::remove(directory_/name,error);
        if(!directory_.empty())std::filesystem::remove(directory_,error);
        directory_.clear();
    }
public:
    ~Parent(){try{stop();}catch(...){cleanup();}}
    bool exists()const{return process_!=nullptr;}
    bool alive()const{return process_&&WaitForSingleObject(process_,0)==WAIT_TIMEOUT;}
    void start(const Json& profile,const Json& options,const std::string& sshPath) {
        if(exists())throw std::runtime_error("Stop the previous native session first");
        auto helper=executableDirectory()/L"FlowBridgeCapture.exe";
        if(!std::filesystem::is_regular_file(helper))throw std::runtime_error("Native helper is missing. Install the internal native-beta package.");
        // Elevated executable and DLL must reside under the protected native
        // installer directory, not in an ordinary per-user installation.
        PWSTR programFiles=nullptr;
        if(FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,0,nullptr,&programFiles)))throw std::runtime_error("Program Files is unavailable");
        auto trusted=std::filesystem::path(programFiles)/L"FlowBridgeBeta";CoTaskMemFree(programFiles);
        if(!std::filesystem::equivalent(helper.parent_path(),trusted))throw std::runtime_error("Native mode requires the protected Program Files\\FlowBridgeBeta installation");
        auto token=guid();PWSTR local=nullptr;
        if(FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData,KF_FLAG_CREATE,nullptr,&local)))throw std::runtime_error("Local AppData unavailable");
        directory_=std::filesystem::path(local)/L"FlowBridge"/L"NativeSessions"/token;CoTaskMemFree(local);
        try {
            std::filesystem::create_directories(directory_);
            write(L"profile.json",profile);write(L"options.json",options);
            auto name=pipeName(token);
            pipe_=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_NOWAIT|PIPE_REJECT_REMOTE_CLIENTS,1,MaxMessage,4096,0,nullptr);
            if(pipe_==INVALID_HANDLE_VALUE){pipe_=nullptr;throw std::runtime_error("Cannot create native control pipe");}
            if(!ConnectNamedPipe(pipe_,nullptr)&&GetLastError()!=ERROR_PIPE_LISTENING)throw std::runtime_error("Cannot listen for native helper");
            auto parameters=L"--console --profile "+quote((directory_/L"profile.json").wstring())+
                L" --native-options "+quote((directory_/L"options.json").wstring())+L" --owner "+std::to_wstring(GetCurrentProcessId())+
                L" --ui-token "+token+L" --bypass "+quote(wide(sshPath));
            SHELLEXECUTEINFOW execute{};execute.cbSize=sizeof(execute);execute.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC;
            execute.lpVerb=L"runas";execute.lpFile=helper.c_str();execute.lpParameters=parameters.c_str();execute.nShow=SW_HIDE;
            if(!ShellExecuteExW(&execute)||!execute.hProcess)throw std::runtime_error("Native activation was cancelled or Windows refused elevation");
            process_=execute.hProcess;started_=observed_=GetTickCount64();last_={{"state","starting"}};
        }catch(...){cleanup();throw;}
    }
    Json poll(bool upstreamReady) {
        if(!exists())return Json::object();
        ULONG client=0;
        if(GetNamedPipeClientProcessId(pipe_,&client)) {
            if(client!=GetProcessId(process_))throw std::runtime_error("Unexpected native pipe client");
            Json message;
            for(unsigned i=0;i<32&&receive(pipe_,message);++i){last_=std::move(message);observed_=GetTickCount64();}
            send(pipe_,{{"ready",upstreamReady}});
        }
        if(!alive()) {
            DWORD code=0;GetExitCodeProcess(process_,&code);
            if(last_.value("state",std::string())!="stopped")last_["error"]=last_.value("error",std::string("Native helper exited: ")+std::to_string(code));
            last_["state"]="stopped";
        }else if(GetTickCount64()-started_>60000&&last_.value("state",std::string())=="starting") {
            send(pipe_,{{"stop",true}});last_["error"]="Native startup deadline exceeded; stopping requested";
        }else if(GetTickCount64()-observed_>10000)last_["warning"]="Native helper heartbeat is overdue; capture state is uncertain";
        return last_;
    }
    void stop() {
        if(!exists())return;
        send(pipe_,{{"stop",true}});
        auto deadline=GetTickCount64()+20000;
        while(alive()&&GetTickCount64()<deadline){try{poll(false);send(pipe_,{{"stop",true}});}catch(...){}Sleep(50);}
        if(alive())throw std::runtime_error("Native helper has not stopped. DNS/capture restoration is not yet confirmed.");
        Json final=last_;cleanup();
        if(final.contains("error"))throw std::runtime_error(final["error"].get<std::string>());
    }
};
}
