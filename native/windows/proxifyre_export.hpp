#pragma once
// Export-only bridge to the separately installed ProxiFyre application.
// No NDIS driver import, install, elevation, packet capture, service control,
// vendor source code or opaque credentials are part of this header.
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include "nlohmann/json.hpp"

namespace proxifyre_export {
using Json = nlohmann::json;

inline std::string lowerAscii(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
    });
    return text;
}

inline std::string normalizedExe(const std::string& value) {
    if (value.size() > 4096 || value.size() < 7 ||
        value[1] != ':' ||
        !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) ||
        (value[2] != '\\' && value[2] != '/'))
        throw std::runtime_error("ProxiFyre export requires an absolute local drive EXE path");
    if (std::any_of(value.begin(), value.end(), [](unsigned char c) {
            return c < 32 || c == 127 || c == '"' || c == '<' || c == '>' ||
                   c == '|' || c == '?' || c == '*';
        }))
        throw std::runtime_error("ProxiFyre application path contains forbidden characters");
    auto source = std::filesystem::u8path(value);
    if (!source.is_absolute())
        throw std::runtime_error("ProxiFyre application path is not absolute");
    for (const auto& part : source)
        if (part == "..")
            throw std::runtime_error("ProxiFyre application path cannot contain parent traversal");
    auto path = source.lexically_normal();
    auto name = lowerAscii(path.filename().u8string());
    if (name.size() <= 4 || name.substr(name.size() - 4) != ".exe")
        throw std::runtime_error("ProxiFyre application must be an .exe");
    // These programs must never be selected for re-proxying: in particular
    // selecting ssh.exe would create a feedback loop through its own SOCKS port.
    static const std::set<std::string> carrier = {
        "flowbridge.exe", "flowbridgecapture.exe", "proxifyre.exe", "ssh.exe"
    };
    if (carrier.count(name))
        throw std::runtime_error("Cannot divert FlowBridge, ProxiFyre or SSH carrier EXE");
    return path.u8string();
}

inline std::string loopbackListener(const Json& config) {
    // ProxiFyre's upstream needs an IPv4 endpoint, not a local DNS name or
    // wildcard listener. It connects to FlowBridge's existing SOCKS5 ingress.
    const auto listen = config.at("listen").get<std::string>();
    constexpr const char* prefix = "127.0.0.1:";
    if (listen.rfind(prefix, 0) != 0)
        throw std::runtime_error("ProxiFyre requires a 127.0.0.1 FlowBridge SOCKS5 listener");
    const std::string portText = listen.substr(10);
    if (portText.empty() || portText.size() > 5 ||
        !std::all_of(portText.begin(), portText.end(), [](unsigned char c) {
            return c >= '0' && c <= '9';
        }))
        throw std::runtime_error("FlowBridge SOCKS5 port is invalid");
    const unsigned long port = std::stoul(portText);
    if (port == 0 || port > 65535)
        throw std::runtime_error("FlowBridge SOCKS5 port is out of range");
    return "127.0.0.1:" + std::to_string(port);
}

inline Json build(const Json& flowbridgeConfig,
                  const std::vector<std::string>& selectedPaths,
                  bool blockOtherApplications) {
    if (blockOtherApplications)
        throw std::runtime_error(
            "ProxiFyre export cannot enforce FlowBridge 'block others'; disable that option");
    if (selectedPaths.empty() || selectedPaths.size() > 64)
        throw std::runtime_error("Select 1-64 applications before ProxiFyre export");
    const auto endpoint = loopbackListener(flowbridgeConfig);
    std::set<std::string> distinct;
    Json appNames = Json::array();
    for (const auto& raw : selectedPaths) {
        const auto path = normalizedExe(raw);
        if (distinct.insert(lowerAscii(path)).second)
            appNames.push_back(path);
    }
    // The rule is intentionally selected-app-only, TCP-only and no wildcard.
    // Other applications remain DIRECT. Remote DNS and UDP/QUIC are not
    // protected here. This is neither a kill-switch nor exact-path identity:
    // vendor path selectors currently use substring matching.
    return Json{
        {"logLevel", "Warning"},
        {"bypassLan", true},
        {"proxies", Json::array({Json{
            {"appNames", appNames},
            {"socks5ProxyEndpoint", endpoint},
            {"socks5Transport", "TCP"},
            {"supportedProtocols", Json::array({"TCP"})},
            {"supportedAddressFamilies", Json::array({"IPv4", "IPv6"})}
        }})},
        {"excludes", Json::array({
            "FlowBridge.exe", "FlowBridgeCapture.exe", "ssh.exe", "ProxiFyre.exe"
        })}
    };
}

} // namespace proxifyre_export
