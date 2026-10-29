#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#ifndef FLOWBRIDGE_IPC_TEST
#error This harness must never be built as the production helper
#endif
#include "../native/windows/native_ipc.hpp"
#include <iostream>
#include <thread>
using native_ipc::Json;
static void require(bool value,const char* message){if(!value)throw std::runtime_error(message);}
static int child(int argc,wchar_t** argv){
    std::wstring token,options;DWORD owner=0;
    for(int i=1;i<argc;++i){std::wstring arg=argv[i];
        if(arg==L"--ui-token"&&i+1<argc)token=argv[++i];
        else if(arg==L"--owner"&&i+1<argc)owner=std::stoul(argv[++i]);
        else if(arg==L"--native-options"&&i+1<argc)options=argv[++i];
    }
    std::ifstream input(std::filesystem::path(options),std::ios::binary);Json settings;input>>settings;
    native_ipc::Child channel;channel.attach(token,owner);
    channel.status({{"state","starting"}});
    auto deadline=GetTickCount64()+10000;bool sawReady=false;
    while(GetTickCount64()<deadline&&channel.alive()){
        Json command;
        if(channel.read(command)){
            if(command.value("stop",false)){
                if(settings.value("fail_stop",false)){channel.status({{"state","faulted"},{"error","synthetic restore failure"}});Sleep(100);return 42;}
                channel.status({{"state","stopped"},{"native",{{"ok",true}}}});Sleep(100);return 0;
            }
            if(command.value("ready",false))sawReady=true;
        }
        if(sawReady)channel.status({{"state","ready"},{"native",{{"status",{{"running",true}}}}}});
        if(settings.value("fail_start",false)&&sawReady){channel.status({{"state","faulted"},{"error","synthetic start failure"}});Sleep(100);return 43;}
        Sleep(20);
    }
    return 44;
}
int wmain(int argc,wchar_t** argv){
    try{
        if(argc>1&&std::wstring(argv[1])==L"--console")return child(argc,argv);
        require(GetEnvironmentVariableW(L"GITHUB_ACTIONS",nullptr,0)!=0,"Run this isolated harness only on GitHub Actions");
        auto dir=native_ipc::executableDirectory();auto helper=dir/L"FlowBridgeCapture.exe";
        require(!std::filesystem::exists(helper),"Test helper already exists; do not replace production helper");
        wchar_t exe[32768]{};require(GetModuleFileNameW(nullptr,exe,32768)!=0,"Missing executable path");
        std::filesystem::copy_file(exe,helper);
        struct Remove{std::filesystem::path path;~Remove(){std::error_code e;std::filesystem::remove(path,e);}} remove{helper};
        for(int mode=0;mode<3;++mode){
            native_ipc::Parent parent;
            parent.start(Json::object(),{{"fail_stop",mode==1},{"fail_start",mode==2}},"C:\\unused-test-ssh.exe");
            auto deadline=GetTickCount64()+10000;Json observed;
            while(GetTickCount64()<deadline){
                observed=parent.poll(true);
                if(mode==2){if(!parent.alive())break;}
                else if(observed.value("state",std::string())=="ready")break;
                Sleep(20);
            }
            if(mode!=2)require(observed.value("state",std::string())=="ready","Verified helper did not become ready");
            bool failed=false;
            try{parent.stop();}catch(const std::exception& e){failed=true;std::cout<<"EXPECTED: "<<e.what()<<"\n";}
            require(failed==(mode!=0),"Stop outcome concealed a failed helper or rejected a clean stop");
            require(!parent.exists(),"Dead helper handles were not released");
        }
        // Verify first-instance and owner checks using a real local pipe but
        // a deliberately incorrect advertised server PID.
        auto token=native_ipc::guid();auto name=native_ipc::pipeName(token);
        HANDLE pipe=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_NOWAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,4096,0,nullptr);
        require(pipe!=INVALID_HANDLE_VALUE,"Cannot create isolated pipe");ConnectNamedPipe(pipe,nullptr);
        STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
        wchar_t system[32768]{};GetSystemDirectoryW(system,32768);
        auto command=std::filesystem::path(system)/L"cmd.exe";
        std::wstring args=native_ipc::quote(command.wstring())+L" /c ping -n 10 127.0.0.1 >nul";
        require(CreateProcessW(command.c_str(),args.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)!=0,"Cannot create wrong-owner fixture");
        bool rejected=false;
        try{native_ipc::Child bad;bad.attach(token,pi.dwProcessId);}catch(...){rejected=true;}
        TerminateProcess(pi.hProcess,0);WaitForSingleObject(pi.hProcess,3000);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(pipe);
        require(rejected,"Wrong pipe owner was accepted");
        std::cout<<"PASS: actual named-pipe peer checks, readiness, clean Stop, failed Stop and failed startup propagation\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<"FAIL: "<<error.what()<<"\n";return 1;}
}
