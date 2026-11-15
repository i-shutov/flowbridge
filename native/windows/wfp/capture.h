#pragma once
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include "redirect_context.h"
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
               const std::vector<std::wstring>& applications);
    void stop() noexcept;
    // Trusted helper must consume exactly one OS-origin AUTH receipt before
    // allowing Rust to open any outbound connection for this accepted flow.
    // This verifies a kernel ticket, not independent kernel socket identity.
    void claim(const FbRedirectContext& context);
private:
    std::mutex ownerMutex_; // serialize worker claim with Stop/driver handle close
    HANDLE driver_ = INVALID_HANDLE_VALUE;
    HANDLE engine_ = nullptr;
};
