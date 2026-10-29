#pragma once
#include <fwpmu.h>
#include <array>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>

// Own the kernel-format full executable identity. Never accept a basename or glob.
class ApplicationId {
public:
    explicit ApplicationId(const std::wstring& path) {
        if (!std::filesystem::path(path).is_absolute() ||
            !std::filesystem::is_regular_file(path))
            throw std::runtime_error("Capture application must be an existing absolute executable path");
        const DWORD error=FwpmGetAppIdFromFileName0(path.c_str(),&blob_);
        if(error) throw std::runtime_error("Resolve capture executable: "+std::to_string(error));
    }
    ~ApplicationId(){ if(blob_) FwpmFreeMemory0(reinterpret_cast<void**>(&blob_)); }
    ApplicationId(const ApplicationId&)=delete;
    ApplicationId& operator=(const ApplicationId&)=delete;
    ApplicationId(ApplicationId&& other) noexcept : blob_(std::exchange(other.blob_,nullptr)) {}
    std::array<FWPM_FILTER_CONDITION0,2> tcpConditions() const {
        std::array<FWPM_FILTER_CONDITION0,2> conditions{};
        conditions[0].fieldKey=FWPM_CONDITION_IP_PROTOCOL;
        conditions[0].matchType=FWP_MATCH_EQUAL;
        conditions[0].conditionValue.type=FWP_UINT8;
        conditions[0].conditionValue.uint8=IPPROTO_TCP;
        conditions[1].fieldKey=FWPM_CONDITION_ALE_APP_ID;
        conditions[1].matchType=FWP_MATCH_EQUAL;
        conditions[1].conditionValue.type=FWP_BYTE_BLOB_TYPE;
        conditions[1].conditionValue.byteBlob=blob_;
        return conditions;
    }
private:
    FWP_BYTE_BLOB* blob_=nullptr;
};
