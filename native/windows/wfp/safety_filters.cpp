#include <winsock2.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <objbase.h>
#include <filesystem>
#include <stdexcept>
#include <array>
#include "safety_filters.hpp"

namespace {
void checkSafety(DWORD status,const char* operation){if(status)throw std::runtime_error(std::string(operation)+": "+std::to_string(status));}
void addBlock(HANDLE engine,const GUID& sublayer,bool ipv6,UINT8 protocol,UINT16 port,FWP_BYTE_BLOB* app){
    std::array<FWPM_FILTER_CONDITION0,4> c{};unsigned count=0;
    auto& p=c[count++];p.fieldKey=FWPM_CONDITION_IP_PROTOCOL;p.matchType=FWP_MATCH_EQUAL;
    p.conditionValue.type=FWP_UINT8;p.conditionValue.uint8=protocol;
    auto& n=c[count++];n.fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;n.matchType=FWP_MATCH_EQUAL;
    n.conditionValue.type=FWP_UINT16;n.conditionValue.uint16=port;
    // Loopback DNS stub and local developer services remain reachable. These
    // address values use the host-order representation required by WFP.
    FWP_V4_ADDR_AND_MASK v4{};v4.addr=0x7f000000;v4.mask=0xff000000;
    FWP_V6_ADDR_AND_MASK v6{};v6.addr[15]=1;v6.prefixLength=128;
    auto& a=c[count++];a.fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;a.matchType=FWP_MATCH_NOT_EQUAL;
    if(ipv6){a.conditionValue.type=FWP_V6_ADDR_MASK;a.conditionValue.v6AddrMask=&v6;}
    else{a.conditionValue.type=FWP_V4_ADDR_MASK;a.conditionValue.v4AddrMask=&v4;}
    if(app){auto& id=c[count++];id.fieldKey=FWPM_CONDITION_ALE_APP_ID;id.matchType=FWP_MATCH_EQUAL;
        id.conditionValue.type=FWP_BYTE_BLOB_TYPE;id.conditionValue.byteBlob=app;}
    FWPM_FILTER0 f{};f.layerKey=ipv6?FWPM_LAYER_ALE_AUTH_CONNECT_V6:FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    f.subLayerKey=sublayer;f.displayData.name=const_cast<wchar_t*>(port==53?L"FlowBridge: no direct standard DNS":L"FlowBridge: selected application QUIC blocked");
    f.action.type=FWP_ACTION_BLOCK;f.weight.type=FWP_EMPTY;f.numFilterConditions=count;f.filterCondition=c.data();
    checkSafety(FwpmFilterAdd0(engine,&f,nullptr,nullptr),"Add leak-prevention filter");
}
}
SafetyFilters::~SafetyFilters(){stop();}
void SafetyFilters::stop() noexcept{if(engine_){FwpmEngineClose0(engine_);engine_=nullptr;}}
void SafetyFilters::start(const std::vector<std::wstring>& applications,bool remoteDns){
    if(engine_)throw std::runtime_error("Safety filters already active");
    if(applications.size()>128)throw std::runtime_error("At most 128 selected QUIC identities");
    for(const auto& path:applications)if(!std::filesystem::path(path).is_absolute()||!std::filesystem::is_regular_file(path))
        throw std::runtime_error("Selected application path is missing or not absolute");
    try{
        FWPM_SESSION0 session{};session.flags=FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name=const_cast<wchar_t*>(L"FlowBridge native leak-prevention lifetime");
        checkSafety(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&session,&engine_),"Open leak-prevention WFP session");
        checkSafety(FwpmTransactionBegin0(engine_,0),"Begin leak-prevention transaction");
        GUID key{};checkSafety(static_cast<DWORD>(CoCreateGuid(&key)),"Create leak-prevention sublayer ID");
        FWPM_SUBLAYER0 layer{};layer.subLayerKey=key;layer.weight=0x100;
        layer.displayData.name=const_cast<wchar_t*>(L"FlowBridge selected QUIC and remote DNS");
        checkSafety(FwpmSubLayerAdd0(engine_,&layer,nullptr),"Add leak-prevention sublayer");
        for(const auto& path:applications){
            FWP_BYTE_BLOB* app=nullptr;checkSafety(FwpmGetAppIdFromFileName0(path.c_str(),&app),"Resolve selected QUIC application");
            try{addBlock(engine_,key,false,IPPROTO_UDP,443,app);addBlock(engine_,key,true,IPPROTO_UDP,443,app);}
            catch(...){FwpmFreeMemory0(reinterpret_cast<void**>(&app));throw;}
            FwpmFreeMemory0(reinterpret_cast<void**>(&app));
        }
        if(remoteDns)for(UINT8 protocol:{static_cast<UINT8>(IPPROTO_UDP),static_cast<UINT8>(IPPROTO_TCP)}){
            addBlock(engine_,key,false,protocol,53,nullptr);addBlock(engine_,key,true,protocol,53,nullptr);
        }
        checkSafety(FwpmTransactionCommit0(engine_),"Commit leak-prevention filters");
    }catch(...){if(engine_)FwpmTransactionAbort0(engine_);stop();throw;}
}
