#pragma once
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include "safety_filters.hpp"
// Exclusive driver owner and dynamic WFP session. Destruction removes only this
// process's filters and disables driver admissions. Listeners must outlive it.
class Capture {
public:
    Capture() = default;
    ~Capture();
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;
    void start(unsigned short port4be, unsigned short port6be,
               const std::vector<std::wstring>& bypass,
               const std::vector<std::wstring>& quicApplications={}, bool remoteDns=false, bool captureAll=true);
    void stop() noexcept;
private:
    HANDLE driver_ = INVALID_HANDLE_VALUE;
    HANDLE engine_ = nullptr;
    SafetyFilters safety_;
};
