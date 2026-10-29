#pragma once
#include <windows.h>
#include <algorithm>
#include <set>
#include <string>
#include <vector>
#include <stdexcept>
#include "nlohmann/json.hpp"
namespace native_profile {
// Process selectors belong only to a separately activated, verified native
// backend. Basenames match the current trusted ALE metadata normalization;
// they are not a publisher/signature assertion or a full-path identity check.
inline nlohmann::json build(nlohmann::json config,const std::vector<std::string>& paths,const std::string& target,bool blockOthers) {
    using Json=nlohmann::json;
    if(paths.empty())throw std::runtime_error("Выберите хотя бы одно приложение.");
    auto found=std::find_if(config.at("proxies").begin(),config.at("proxies").end(),[&](const Json& p){return p.value("id",std::string())==target;});
    if(found==config.at("proxies").end())throw std::runtime_error("Выбранный upstream-прокси отсутствует в профиле.");
    std::set<std::string> names;
    for(const auto& path:paths){auto name=path.substr(path.find_last_of("/\\")+1);if(name.empty())throw std::runtime_error("У приложения нет имени EXE.");std::transform(name.begin(),name.end(),name.begin(),[](unsigned char c){return c>='A'&&c<='Z'?static_cast<char>(c-'A'+'a'):static_cast<char>(c);});names.insert(name);}
    Json applications=Json::array();for(const auto& name:names)applications.push_back(name);
    Json rule={{"id","selected-applications"},{"enabled",true},{"applications",applications},{"hosts",Json::array()},{"networks",Json::array()},{"ports",Json::array()},{"action",{{"type","proxy"},{"id",target}}}};
    config["rules"]=Json::array({rule});config["default_action"]={{"type",blockOthers?"block":"direct"}};return config;
}

// A GUI-owned managed SSH must remain in the unelevated process. Native WFP
// capture connects only to the existing user-level FlowBridge SOCKS listener,
// which already has a readiness gate and the supervised SSH backend. Never
// serialize the SSH identity file, known_hosts or other user secrets into the
// elevated helper's configuration.
inline nlohmann::json viaUserOwnedSsh(nlohmann::json config,
                                      const std::vector<std::string>& selected) {
    using Json=nlohmann::json;
    const auto listen=config.at("listen").get<std::string>();
    std::string host,portText;
    if(listen.rfind("127.0.0.1:",0)==0) {
        host="127.0.0.1";portText=listen.substr(10);
    } else if(listen.rfind("[::1]:",0)==0) {
        host="::1";portText=listen.substr(6);
    } else throw std::runtime_error("GUI-owned SSH capture requires a loopback-only FlowBridge listener");
    if(portText.empty()||portText.size()>5||
       !std::all_of(portText.begin(),portText.end(),[](unsigned char c){return c>='0'&&c<='9';}))
        throw std::runtime_error("GUI-owned SSH listener port is invalid");
    const auto port=std::stoul(portText);
    if(port==0||port>65535)throw std::runtime_error("GUI-owned SSH listener port is out of range");
    Json upstream={{"id","gui-owned-socks"},{"kind","socks5"},
                   {"endpoint",{{"host",host},{"port",port}}},
                   {"username",nullptr},{"password_env",nullptr}};
    // Important: do not inherit other proxy chains, credentials or arbitrary
    // rules in the elevated helper. The user-mode engine applies those rules.
    config["proxies"]=Json::array({upstream});
    config["chains"]=Json::array();
    return build(std::move(config),selected,"gui-owned-socks",false);
}

}
