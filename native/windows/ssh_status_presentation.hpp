#pragma once

#include <string>

namespace ssh_status_presentation {
inline std::string summary(const std::string& health) {
    return health.substr(0, health.find_first_of("\r\n"));
}

inline void append_changed_error(std::string& journal, std::string& previous,
                                 const std::string& error) {
    if (!error.empty() && error != previous) journal += "\r\n[SSH / error] " + error;
    previous = error;
}
}
