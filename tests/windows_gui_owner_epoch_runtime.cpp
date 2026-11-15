// Actual Windows process-object/creation-time trust regression.
// Executes Win32 GetProcessTimes, GetProcessId, OpenProcess semantics without
// a network driver, service, BFE filter or system configuration modification.
// A pass CANNOT identify the process that originated an NDISRD packet.
#include <windows.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "gui_owner_epoch.hpp"

static void require(bool ok, const char* diagnostic) {
    if (!ok) throw std::runtime_error(diagnostic);
}
template<class Operation> static bool rejected(Operation operation) {
    try { operation(); } catch (const std::exception&) { return true; }
    return false;
}
struct AutoHandle {
    HANDLE h=nullptr;
    ~AutoHandle() { if (h && h!=INVALID_HANDLE_VALUE) CloseHandle(h); }
    AutoHandle(const AutoHandle&)=delete;
    AutoHandle& operator=(const AutoHandle&)=delete;
    explicit AutoHandle(HANDLE value):h(value){}
};
static bool actualProcessCreation() {
    auto epoch=gui_owner_epoch::current();
    require(epoch>0,"zero_or_absent_actual_creation_epoch");
    require(gui_owner_epoch::creationTime(GetCurrentProcess())==epoch,
            "self_epoch_not_stable");
    gui_owner_epoch::verify(GetCurrentProcess(),GetCurrentProcessId(),epoch);
    AutoHandle other{OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,GetCurrentProcessId())};
    require(other.h!=nullptr,"open_real_self_process_failed");
    gui_owner_epoch::verify(other.h,GetCurrentProcessId(),epoch);
    return true;
}
static bool wrongPidRejected() {
    return rejected([]{
        gui_owner_epoch::verify(GetCurrentProcess(),GetCurrentProcessId()+1,gui_owner_epoch::current());
    });
}
static bool wrongEpochRejected() {
    return rejected([]{
        gui_owner_epoch::verify(GetCurrentProcess(),GetCurrentProcessId(),gui_owner_epoch::current()-1);
    });
}
static bool missingEpochRejected() {
    return rejected([]{
        gui_owner_epoch::verify(GetCurrentProcess(),GetCurrentProcessId(),0);
    });
}
static bool stoppedOwnerRejected() {
    wchar_t dir[MAX_PATH]{};
    UINT size=GetSystemDirectoryW(dir,MAX_PATH);
    require(size>0 && size<MAX_PATH,"system_cmd_path_unavailable");
    const auto cmd=(std::filesystem::path(dir)/L"cmd.exe").wstring();
    require(std::filesystem::is_regular_file(cmd),"system_cmd_missing");
    std::wstring line=L"\""+cmd+L"\" /d /c exit /b 0";
    std::vector<wchar_t> text(line.begin(),line.end());
    text.push_back(L'\0');
    STARTUPINFOW si{}; si.cb=sizeof(si);
    PROCESS_INFORMATION pi{};
    require(CreateProcessW(cmd.c_str(),text.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,
                           nullptr,nullptr,&si,&pi)!=0,"disposable_child_create_failed");
    AutoHandle process{pi.hProcess}, thread{pi.hThread};
    const auto epoch=gui_owner_epoch::creationTime(process.h);
    const DWORD status=WaitForSingleObject(process.h,10000);
    if(status!=WAIT_OBJECT_0) {
        TerminateProcess(process.h,1);
        WaitForSingleObject(process.h,2000);
        throw std::runtime_error("disposable_child_exit_timeout");
    }
    // The terminated process still has a valid handle and creation time.
    // This must never authorize a stale listener with its PID.
    require(gui_owner_epoch::creationTime(process.h)==epoch,
            "terminated_handle_lost_creation_epoch");
    return rejected([&]{gui_owner_epoch::verify(process.h,pi.dwProcessId,epoch);});
}
int wmain(int argc,wchar_t** argv) {
    try {
        const std::wstring selected=argc==3 && std::wstring(argv[1])==L"--case"
            ? std::wstring(argv[2]) : L"all";
        if(selected!=L"all" && selected!=L"pid" && selected!=L"epoch" &&
           selected!=L"missing" && selected!=L"exit")
            throw std::runtime_error("unknown_test_case");
        if(selected==L"all" || selected==L"pid")
            require(actualProcessCreation() && wrongPidRejected(),"pid_mismatch_not_rejected");
        if(selected==L"all" || selected==L"epoch")
            require(actualProcessCreation() && wrongEpochRejected(),"epoch_mismatch_not_rejected");
        if(selected==L"all" || selected==L"missing")
            require(missingEpochRejected(),"missing_epoch_not_rejected");
        if(selected==L"all" || selected==L"exit")
            require(stoppedOwnerRejected(),"exited_owner_not_rejected");
        if(selected==L"all") {
            std::cout<<"{\"schema\":\"flowbridge-windows-gui-owner-epoch-v1\","
                     <<"\"status\":\"PASS_REAL_WIN32_PROCESS_HANDLE_TEST\","
                     <<"\"actual_os_creation_time_checked\":true,"
                     <<"\"wrong_pid_rejected\":true,"
                     <<"\"wrong_creation_epoch_rejected\":true,"
                     <<"\"missing_epoch_rejected\":true,"
                     <<"\"terminated_process_rejected\":true,"
                     <<"\"driver_installed\":false,"
                     <<"\"wfp_changed\":false,"
                     <<"\"ndisrd_packet_origin_verified\":false,"
                     <<"\"g2_packet_bound_accepted\":false,"
                     <<"\"release_accepted\":false}"<<std::endl;
        } else {
            std::wcout<<L"PASS "<<selected<<L" real Windows process-object check"<<std::endl;
        }
        return 0;
    } catch(const std::exception& error) {
        std::cerr<<"FAIL "<<error.what()<<std::endl;
        return 1;
    }
}
