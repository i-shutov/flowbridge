#pragma once

#include <string>

namespace ssh_status_presentation {
inline std::string summary(const std::string& health) {
    return health.substr(0, health.find_first_of("\r\n"));
}

inline void append_health(std::string& journal, const std::string& health) {
    if (health.empty()) return;
    const auto record = "\r\n[SSH / status] " + health;
    if (journal.find(record) == std::string::npos) journal += record;
}
}
