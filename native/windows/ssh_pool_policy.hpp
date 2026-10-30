#pragma once
#include <cstdint>
#include <set>
#include <stdexcept>
#include <vector>
#include "nlohmann/json.hpp"

// Shared by the actual Win32 worker and its compiled native regression.
namespace ssh_pool_policy {
inline nlohmann::json ownedRequest(const std::vector<uint64_t>& ids,bool enabled) {
    const auto count=ids.size();
    if(count<2||count>4||std::set<uint64_t>(ids.begin(),ids.end()).size()!=count)
        throw std::runtime_error("SSH pool requires 2-4 distinct owned supervisors.");
    for(auto id:ids)if(!id)throw std::runtime_error("Invalid SSH supervisor handle.");
    const auto flows=128/count;
    return {{"ssh_ids",ids},{"enabled",enabled},
        {"limits",{{"max_flows",flows},{"max_opening",16},
                   {"max_queued",64/count},{"wait_timeout_ms",10000}}},
        {"aggregate_max_flows",128}};
}
inline bool captureAvailable(bool managed,bool engineRunning,bool pendingStart,
                             bool tunnelReady,bool busy,bool closing,
                             bool captureActive,bool captureStopping) {
    if(busy||closing||pendingStart||captureActive||captureStopping)return false;
    // Managed capture deliberately USES the running user-owned engine.
    // External capture is a separate helper and must not compete with it.
    return managed ? engineRunning&&tunnelReady : !engineRunning;
}
}
