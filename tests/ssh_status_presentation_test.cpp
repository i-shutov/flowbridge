#include "../native/windows/ssh_status_presentation.hpp"
#include <cstdio>
#include <string>

int main() {
    using namespace ssh_status_presentation;
    const std::string longPath = "C:/" + std::string(4096, 'p') + "/ssh.exe";
    const std::string longError = "authentication failed: " + std::string(4096, 'e');
    for (const std::string& state : {"Ready", "Failed", "Degraded", "Reconnecting"}) {
        const std::string line = "SSH 1/1 - " + state + " - restarts 123";
        const std::string health = line + "\r\n" + longError + "\r\n" + longPath;
        const auto compact = summary(health);
        if (compact != line || compact.find_first_of("\r\n") != std::string::npos) return 1;
    }
    if (summary("ready\nerror") != "ready" || summary("ready\rerror") != "ready" ||
        summary("ready") != "ready" || !summary("").empty()) return 2;
    std::string journal = "previous", previous;
    append_changed_error(journal, previous, longError);
    if (journal != "previous\r\n[SSH / error] " + longError) return 3;
    const auto once = journal;
    append_changed_error(journal, previous, longError);
    if (journal != once) return 4;
    append_changed_error(journal, previous, "");
    append_changed_error(journal, previous, longError);
    if (journal != once + "\r\n[SSH / error] " + longError) return 5;
    std::puts("SSH status presentation regression PASS");
    return 0;
}
