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
}
