#pragma once
#include <windows.h>
#include <cstdint>
#include <stdexcept>
#include <string>

// Win32 process lifetime evidence for the GUI-to-UAC-helper handshake.
// This is NOT attribution for a network packet or a WFP/NDISRD flow.
// The elevated helper retains the verified HANDLE for its whole lifetime,
// preventing PID reuse while that owner relationship is in force.
namespace gui_owner_epoch {
inline std::uint64_t creationTime(HANDLE process) {
    // GetCurrentProcess() is the valid pseudo-handle (HANDLE)-1, which equals
    // INVALID_HANDLE_VALUE numerically. Never reject it as a generic error.
    // OpenProcess failures are NULL and checked separately at the call site.
    if (!process)
        throw std::runtime_error("GUI owner process handle unavailable");
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user))
        throw std::runtime_error("Cannot query OS GUI owner process creation time");
    const auto epoch = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) |
                       static_cast<std::uint64_t>(created.dwLowDateTime);
    if (!epoch) throw std::runtime_error("GUI owner process creation time is empty");
    return epoch;
}
inline std::uint64_t current() {
    return creationTime(GetCurrentProcess());
}
inline void verify(HANDLE owner, DWORD expectedPid, std::uint64_t expectedEpoch) {
    if (!expectedPid || !expectedEpoch || !owner)
        throw std::runtime_error("GUI owner PID and creation time are mandatory");
    if (GetProcessId(owner) != expectedPid)
        throw std::runtime_error("GUI owner process handle PID changed");
    if (creationTime(owner) != expectedEpoch)
        throw std::runtime_error("GUI owner PID was reused or creation time mismatched");
    // A handle for a terminated process still returns its old creation time.
    // Never accept it as the owner of a live SOCKS listener.
    if (WaitForSingleObject(owner, 0) != WAIT_TIMEOUT)
        throw std::runtime_error("GUI owner process is no longer running");
}
} // namespace gui_owner_epoch
