#pragma once
// Include winsock2/windows/fwpmu once in the caller before this helper.
// fwpmu GUID definitions are intentionally outside its ordinary include guard;
// re-including it in an INITGUID translation unit defines every GUID twice.
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
        // Environment variables (notably TEMP) may contain 8.3 aliases. WFP's
        // application identity must use the normalized image path, not an alias.
        HANDLE file=CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Open capture executable: "+std::to_string(GetLastError()));
        struct FileGuard {HANDLE value;~FileGuard(){CloseHandle(value);}} guard{file};
        std::wstring normalized(32768,L'\0');
        const DWORD count=GetFinalPathNameByHandleW(file,normalized.data(),
            static_cast<DWORD>(normalized.size()),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
        if(!count || count>=normalized.size())throw std::runtime_error("Normalize capture executable: "+std::to_string(GetLastError()));
        normalized.resize(count);
        if(normalized.rfind(LR"(\\?\UNC\)",0)==0)normalized=LR"(\\)"+normalized.substr(8);
        else if(normalized.rfind(LR"(\\?\)",0)==0)normalized.erase(0,4);
        const DWORD error=FwpmGetAppIdFromFileName0(normalized.c_str(),&blob_);
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
