#include "capture.h"
#include <initguid.h>
#include <fwpmu.h>
#include <winioctl.h>
#include <stdexcept>
#include <memory>
#include "control.h"
// MinGW ships management declarations but omits many SDK GUID declarations.
// A Microsoft SDK build provides/defines these through fwpmu.h/initguid.h.
#ifdef __MINGW32__
DEFINE_GUID(FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,0xc6e63c8c,0xb784,0x4562,0xaa,0x7d,0x0a,0x67,0xcf,0xca,0xf9,0xa3);
DEFINE_GUID(FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,0x587e54a7,0x8046,0x42ba,0xa0,0xaa,0xb7,0x16,0x25,0x0f,0xc7,0xfd);
DEFINE_GUID(FWPM_CONDITION_IP_PROTOCOL,0x3971ef2b,0x623e,0x4f9a,0x8c,0xb1,0x6e,0x79,0xb8,0x06,0xb9,0xa7);
DEFINE_GUID(FWPM_CONDITION_ALE_APP_ID,0xd78e1e87,0x8644,0x4ea5,0x94,0x37,0xd8,0x09,0xec,0xef,0xc9,0x71);
#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 1
#endif
#ifndef FWPM_CALLOUT_FLAG_REGISTERED
#define FWPM_CALLOUT_FLAG_REGISTERED 0x00040000
#endif
#endif
namespace {
void check(DWORD error, const char* what) {
    if (error) throw std::runtime_error(std::string(what)+": "+std::to_string(error));
}
void ioctl(HANDLE driver, DWORD operation, void* input, DWORD length) {
    DWORD returned=0;
    if (!DeviceIoControl(driver,operation,input,length,nullptr,0,&returned,nullptr))
        check(GetLastError(),"Driver configuration");
}
void verifyCallout(HANDLE engine, const GUID& key) {
    FWPM_CALLOUT0* raw=nullptr;
    check(FwpmCalloutGetByKey0(engine,&key,&raw),"Query registered callout");
    bool registered=(raw->flags & FWPM_CALLOUT_FLAG_REGISTERED)!=0;
    FwpmFreeMemory0(reinterpret_cast<void**>(&raw));
    if (!registered) throw std::runtime_error("Kernel callout is not registered");
}
}
Capture::~Capture() { stop(); }
void Capture::stop() noexcept {
    // Dynamic session close atomically removes admissions before listeners stop.
    if (engine_) { FwpmEngineClose0(engine_); engine_=nullptr; }
    if (driver_!=INVALID_HANDLE_VALUE) {
        DWORD count=0; DeviceIoControl(driver_,FB_IOCTL_DISABLE,nullptr,0,nullptr,0,&count,nullptr);
        CloseHandle(driver_); driver_=INVALID_HANDLE_VALUE;
    }
}
void Capture::start(unsigned short p4, unsigned short p6, const std::vector<std::wstring>& bypass) {
    if (engine_ || driver_!=INVALID_HANDLE_VALUE) throw std::runtime_error("Capture already started");
    if (bypass.size()>16) throw std::runtime_error("At most sixteen bypass executable paths");
    try {
        driver_=CreateFileW(FB_WFP_DEVICE,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
        if (driver_==INVALID_HANDLE_VALUE) check(GetLastError(),"Open signed WFP driver");
        FbWfpStatus status{}; DWORD count=0;
        if (!DeviceIoControl(driver_,FB_IOCTL_QUERY,nullptr,0,&status,sizeof(status),&count,nullptr)) check(GetLastError(),"Query driver ABI");
        if (count!=sizeof(status) || status.size!=sizeof(status) || status.version!=FB_WFP_ABI || status.service_pid!=GetCurrentProcessId())
            throw std::runtime_error("Driver ABI/owner mismatch");
        FWPM_SESSION0 session{}; session.flags=FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name=const_cast<wchar_t*>(L"FlowBridge TCP capture lifetime");
        check(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&session,&engine_),"Open WFP session");
        check(FwpmTransactionBegin0(engine_,0),"Begin capture transaction");
        FWPM_PROVIDER0 provider{}; provider.providerKey=FB_WFP_PROVIDER;
        provider.displayData.name=const_cast<wchar_t*>(L"FlowBridge");
        check(FwpmProviderAdd0(engine_,&provider,nullptr),"Add provider");
        FWPM_SUBLAYER0 layer{}; layer.subLayerKey=FB_WFP_SUBLAYER;
        layer.providerKey=const_cast<GUID*>(&FB_WFP_PROVIDER); layer.weight=0x100;
        layer.displayData.name=const_cast<wchar_t*>(L"FlowBridge TCP redirect");
        check(FwpmSubLayerAdd0(engine_,&layer,nullptr),"Add sublayer");
        const GUID layers[]={FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,FWPM_LAYER_ALE_CONNECT_REDIRECT_V6};
        const GUID keys[]={FB_WFP_CALLOUT4,FB_WFP_CALLOUT6};
        for (unsigned i=0;i<2;++i) {
            FWPM_CALLOUT0 callout{}; callout.calloutKey=keys[i]; callout.applicableLayer=layers[i];
            callout.providerKey=const_cast<GUID*>(&FB_WFP_PROVIDER);
            callout.displayData.name=const_cast<wchar_t*>(L"FlowBridge TCP callout");
            check(FwpmCalloutAdd0(engine_,&callout,nullptr,nullptr),"Add callout");
            verifyCallout(engine_,keys[i]);
            FWPM_FILTER_CONDITION0 tcp{}; tcp.fieldKey=FWPM_CONDITION_IP_PROTOCOL;
            tcp.matchType=FWP_MATCH_EQUAL; tcp.conditionValue.type=FWP_UINT8; tcp.conditionValue.uint8=IPPROTO_TCP;
            FWPM_FILTER0 filter{}; filter.layerKey=layers[i]; filter.subLayerKey=FB_WFP_SUBLAYER;
            filter.providerKey=const_cast<GUID*>(&FB_WFP_PROVIDER);
            filter.displayData.name=const_cast<wchar_t*>(L"FlowBridge capture TCP");
            UINT64 captureWeight=1, bypassWeight=100;
            filter.weight.type=FWP_UINT64; filter.weight.uint64=&captureWeight;
            filter.action.type=FWP_ACTION_CALLOUT_TERMINATING; filter.action.calloutKey=keys[i];
            filter.numFilterConditions=1; filter.filterCondition=&tcp;
            check(FwpmFilterAdd0(engine_,&filter,nullptr,nullptr),"Add TCP filter");
            for (const auto& path:bypass) {
                FWP_BYTE_BLOB* app=nullptr;
                check(FwpmGetAppIdFromFileName0(path.c_str(),&app),"Resolve bypass executable");
                FWPM_FILTER_CONDITION0 condition{}; condition.fieldKey=FWPM_CONDITION_ALE_APP_ID;
                condition.matchType=FWP_MATCH_EQUAL; condition.conditionValue.type=FWP_BYTE_BLOB_TYPE; condition.conditionValue.byteBlob=app;
                // Separate high-weight permit filters avoid OR semantics for
                // repeated NOT_EQUAL conditions on the same app-id field.
                filter.action.type=FWP_ACTION_PERMIT; filter.weight.uint64=&bypassWeight;
                filter.filterCondition=&condition;
                filter.displayData.name=const_cast<wchar_t*>(L"FlowBridge explicit executable bypass");
                DWORD result=FwpmFilterAdd0(engine_,&filter,nullptr,nullptr);
                FwpmFreeMemory0(reinterpret_cast<void**>(&app)); check(result,"Add bypass filter");
            }
        }
        FbWfpConfig config{sizeof(FbWfpConfig),FB_WFP_ABI,p4,p6,0};
        ioctl(driver_,FB_IOCTL_CONFIGURE,&config,sizeof(config));
        check(FwpmTransactionCommit0(engine_),"Commit capture filters");
    } catch (...) { if (engine_) FwpmTransactionAbort0(engine_); stop(); throw; }
}
