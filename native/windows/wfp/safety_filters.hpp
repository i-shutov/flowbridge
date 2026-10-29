#pragma once
#include <windows.h>
#include <string>
#include <vector>

// Built-in WFP block actions; no third-party callout/driver needed for these
// leak-prevention rules. They are scoped to a dynamic process-owned session.
class SafetyFilters {
public:
    SafetyFilters()=default;
    ~SafetyFilters();
    SafetyFilters(const SafetyFilters&)=delete;
    SafetyFilters& operator=(const SafetyFilters&)=delete;
    void start(const std::vector<std::wstring>& quicApplications,bool remoteDns);
    void stop() noexcept;
private:
    HANDLE engine_=nullptr;
};
