#pragma once

#include <string>

namespace ssh_status_presentation {
inline std::string summary(const std::string& health) {
    return health.substr(0, health.find_first_of("\r\n"));
}

inline void append_changed_health(std::string& journal, std::string& previous,
                                  const std::string& health) {
    if (!health.empty() && health != previous) journal += "\r\n[SSH / status] " + health;
    previous = health;
}
}
