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
        std::string journal;
        append_health(journal, health);
        if (journal != "\r\n[SSH / status] " + health ||
            journal.find(longError) == std::string::npos || journal.find(longPath) == std::string::npos) return 3;
        const auto once = journal;
        append_health(journal, health);
        if (journal != once) return 4;
        // The engine snapshot rebuilds the journal on a later poll, even
        // when the SSH health string did not change.
        journal = "engine snapshot";
        append_health(journal, health);
        if (journal != "engine snapshot\r\n[SSH / status] " + health) return 5;
        append_health(journal, "");
        if (journal != "engine snapshot\r\n[SSH / status] " + health) return 6;
    }
    if (summary("ready\nerror") != "ready" || summary("ready\rerror") != "ready" ||
        summary("ready") != "ready" || !summary("").empty()) return 2;
    std::puts("SSH status presentation regression PASS");
    return 0;
}
