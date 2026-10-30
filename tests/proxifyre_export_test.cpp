#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "../native/windows/proxifyre_export.hpp"

#define CHECK(condition) do { if (!(condition)) throw std::runtime_error("ProxiFyre profile regression failed: " #condition); } while(false)

using Json = nlohmann::json;

template <typename Fn> void mustReject(Fn&& fn, const std::string& expected) {
    bool rejected = false;
    try { fn(); }
    catch (const std::exception& ex) {
        rejected = true;
        CHECK(std::string(ex.what()).find(expected) != std::string::npos);
    }
    CHECK(rejected);
}

int main() {
    Json privateSource = {
        {"listen", "127.0.0.1:1081"},
        {"password_env", "MY_SECRET"},
        {"identity_file", R"(C:\private\id_ed25519)"},
        {"known_hosts_file", R"(C:\private\known_hosts)"},
        {"username", "do_not_export"}
    };
    auto exported = proxifyre_export::build(privateSource, {
        R"(C:\Program Files\Browser\chrome.exe)",
        R"(c:\program files\browser\CHROME.EXE)",
        R"(C:\Apps\Claude.exe)"
    }, false);
    CHECK(exported["proxies"].size() == 1);
    CHECK(exported["proxies"][0]["appNames"].size() == 2);
    CHECK(exported["proxies"][0]["socks5ProxyEndpoint"] == "127.0.0.1:1081");
    CHECK(exported["proxies"][0]["socks5Transport"] == "TCP");
    CHECK(exported["proxies"][0]["supportedProtocols"] == Json::array({"TCP"}));
    CHECK(exported["proxies"][0]["supportedAddressFamilies"] == Json::array({"IPv4", "IPv6"}));
    CHECK(exported["bypassLan"] == true);
    CHECK(exported["logLevel"] == "Warning");
    CHECK(exported["excludes"].size() == 4);
    CHECK(exported["proxies"][0]["appNames"][0].get<std::string>().find('\\') != std::string::npos);
    CHECK(exported.dump().find("do_not_export") == std::string::npos);
    CHECK(exported.dump().find("MY_SECRET") == std::string::npos);
    CHECK(exported.dump().find("id_ed25519") == std::string::npos);
    CHECK(exported.dump().find("known_hosts") == std::string::npos);
    CHECK(exported.dump().find(R"("appNames":[""])") == std::string::npos);
    mustReject([&]{ proxifyre_export::build(privateSource, {}, false); }, "1-64");
    mustReject([&]{ proxifyre_export::build(privateSource, {R"(C:\Apps\chrome.exe)"}, true); }, "block others");
    mustReject([&]{ proxifyre_export::build(privateSource, {"relative.exe"}, false); }, "absolute");
    mustReject([&]{ proxifyre_export::build(privateSource, {R"(C:\Apps\..\ssh.exe)"}, false); }, "parent traversal");
    mustReject([&]{ proxifyre_export::build(privateSource, {R"(C:\Windows\System32\OpenSSH\ssh.exe)"}, false); }, "carrier");
    mustReject([&]{ proxifyre_export::build(privateSource, {R"(C:\Apps\FlowBridge.exe)"}, false); }, "carrier");
    mustReject([&]{ proxifyre_export::build(privateSource, {R"(\\server\share\app.exe)"}, false); }, "absolute local drive");
    mustReject([&]{ proxifyre_export::build(privateSource, {R"(C:\Apps\bad?.exe)"}, false); }, "forbidden");
    mustReject([&]{ proxifyre_export::build(privateSource, {R"(C:\Apps\app.com)"}, false); }, ".exe");
    Json external = privateSource;
    external["listen"] = "0.0.0.0:1081";
    mustReject([&]{ proxifyre_export::build(external, {R"(C:\Apps\chrome.exe)"}, false); }, "127.0.0.1");
    external["listen"] = "[::1]:1081";
    mustReject([&]{ proxifyre_export::build(external, {R"(C:\Apps\chrome.exe)"}, false); }, "127.0.0.1");
    external["listen"] = "127.0.0.1:0";
    mustReject([&]{ proxifyre_export::build(external, {R"(C:\Apps\chrome.exe)"}, false); }, "out of range");
    external["listen"] = "127.0.0.1:65536";
    mustReject([&]{ proxifyre_export::build(external, {R"(C:\Apps\chrome.exe)"}, false); }, "out of range");
    external["listen"] = "127.0.0.1:1081:0";
    mustReject([&]{ proxifyre_export::build(external, {R"(C:\Apps\chrome.exe)"}, false); }, "invalid");
    std::cout << "PASS ProxiFyre export: selected paths, TCP-only, carrier bypass, no secrets and strict negatives\n";
}
