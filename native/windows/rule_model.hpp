#pragma once
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "nlohmann/json.hpp"

// Pure model shared by the Win32 rule UI and its independent regression.
// Caller must supply the existing strict Rust-FFI validation callback.
namespace rule_editor {
using Json=nlohmann::json;

inline std::string trim(std::string s) {
    const auto start=s.find_first_not_of(" \t\r\n");
    if(start==std::string::npos) return {};
    const auto end=s.find_last_not_of(" \t\r\n");
    return s.substr(start,end-start+1);
}
inline std::vector<std::string> list(const std::string& text) {
    std::vector<std::string> values;
    std::string item;
    auto flush=[&]{auto s=trim(item);if(!s.empty())values.push_back(s);item.clear();};
    for(char c:text){if(c==';'||c=='\n'||c=='\r')flush();else item.push_back(c);}
    flush(); return values;
}
inline std::string joined(const Json& values){
    std::string result;
    for(const auto& item:values){if(!result.empty())result+="; ";result+=item.get<std::string>();}
    return result;
}
inline uint16_t port(const std::string& value) {
    const auto s=trim(value);
    if(s.empty()||!std::all_of(s.begin(),s.end(),[](unsigned char c){return c>='0'&&c<='9';}))
        throw std::invalid_argument("Порт должен быть целым числом от 1 до 65535.");
    if(s.size()>5) throw std::invalid_argument("Порт вне диапазона 1–65535.");
    unsigned long result=std::stoul(s);
    if(result==0||result>65535)throw std::invalid_argument("Порт вне диапазона 1–65535.");
    return static_cast<uint16_t>(result);
}
inline Json ranges(const std::string& text) {
    Json result=Json::array();
    for(const auto& item:list(text)){
        const auto dash=item.find('-');
        if(dash!=std::string::npos&&item.find('-',dash+1)!=std::string::npos)
            throw std::invalid_argument("Диапазон портов имеет формат 8000-8010.");
        const auto start=port(dash==std::string::npos?item:item.substr(0,dash));
        const auto end=dash==std::string::npos?start:port(item.substr(dash+1));
        if(start>end)throw std::invalid_argument("Начальный порт больше конечного.");
        result.push_back({{"start",start},{"end",end}});
    }
    return result;
}
inline std::string showRanges(const Json& items) {
    std::string text;
    for(const auto& r:items){
        if(!text.empty())text+="; ";
        auto a=r.at("start").get<int>(),b=r.at("end").get<int>();
        text+=std::to_string(a);
        if(a!=b)text+="-"+std::to_string(b);
    }
    return text;
}
struct Fields {
    std::string id,applications,hosts,networks,ports;
    Json action={{"type","direct"}};
    bool enabled=false;
};
inline Json toRule(const Fields& input) {
    Json n=Json::object();
    n["id"]=trim(input.id);
    n["enabled"]=input.enabled;
    n["applications"]=list(input.applications);
    n["hosts"]=list(input.hosts);
    n["networks"]=list(input.networks);
    n["ports"]=ranges(input.ports);
    n["action"]=input.action;
    return n;
}
inline Fields toFields(const Json& rule){
    Fields f;
    f.id=rule.at("id").get<std::string>();
    f.enabled=rule.at("enabled").get<bool>();
    f.applications=joined(rule.at("applications"));
    f.hosts=joined(rule.at("hosts"));
    f.networks=joined(rule.at("networks"));
    f.ports=showRanges(rule.at("ports"));
    f.action=rule.at("action");
    return f;
}
inline std::string actionName(const Json& action){
    const auto type=action.at("type").get<std::string>();
    if(type=="direct")return "Direct";
    if(type=="block")return "Block";
    return type+": "+action.at("id").get<std::string>();
}
inline std::vector<Json> choices(const Json& config){
    std::vector<Json> options={{{"type","direct"}},{{"type","block"}}};
    for(const auto& p:config.at("proxies"))options.push_back({{"type","proxy"},{"id",p.at("id")}});
    for(const auto& c:config.at("chains"))options.push_back({{"type","chain"},{"id",c.at("id")}});
    return options;
}
class Model {
    Json config_;
    template<typename Validator>
    void commit(Json candidate,Validator&& validate){
        validate(candidate.dump());
        config_=std::move(candidate);
    }
    std::string uniqueId(const std::string& prefix)const{
        for(unsigned long n=1;n<100000;++n){
            std::string id=prefix+std::to_string(n);
            bool used=false;
            for(const auto& r:config_.at("rules")) if(r.at("id")==id){used=true;break;}
            if(!used)return id;
        }
        throw std::runtime_error("Не удалось найти свободный ID правила.");
    }
public:
    explicit Model(Json initial):config_(std::move(initial)){
        if(!config_.is_object()||!config_.contains("rules")||!config_["rules"].is_array()||
           !config_.contains("proxies")||!config_["proxies"].is_array()||
           !config_.contains("chains")||!config_["chains"].is_array())
            throw std::invalid_argument("Неверная структура профиля правил.");
    }
    const Json& config()const{return config_;}
    size_t size()const{return config_.at("rules").size();}
    const Json& rule(size_t index)const{return config_.at("rules").at(index);}
    template<typename Validator>
    size_t add(Validator&& validate){
        Json candidate=config_;Fields fields;
        fields.id=uniqueId("rule-"); // deliberately disabled: never intercept all traffic on Add
        candidate["rules"].push_back(toRule(fields));
        commit(std::move(candidate),std::forward<Validator>(validate));return size()-1;
    }
    template<typename Validator>
    size_t duplicate(size_t index,Validator&& validate){
        Json candidate=config_;
        Json copy=candidate.at("rules").at(index);
        copy["id"]=uniqueId(copy.at("id").get<std::string>()+"-copy-");
        copy["enabled"]=false;
        candidate["rules"].insert(candidate["rules"].begin()+static_cast<std::ptrdiff_t>(index)+1,std::move(copy));
        commit(std::move(candidate),std::forward<Validator>(validate));return index+1;
    }
    template<typename Validator>
    void update(size_t index,const Fields& fields,Validator&& validate){
        Json candidate=config_;
        candidate.at("rules").at(index)=toRule(fields);
        commit(std::move(candidate),std::forward<Validator>(validate));
    }
    template<typename Validator>
    void erase(size_t index,Validator&& validate){
        Json candidate=config_;
        candidate.at("rules").erase(candidate["rules"].begin()+static_cast<std::ptrdiff_t>(index));
        commit(std::move(candidate),std::forward<Validator>(validate));
    }
    template<typename Validator>
    size_t move(size_t index,int direction,Validator&& validate){
        if(direction!=1&&direction!=-1)throw std::invalid_argument("Неверное направление правила.");
        if(index>=size()||(direction==-1&&index==0)||(direction==1&&index+1>=size()))
            throw std::out_of_range("Правило уже на границе списка.");
        Json candidate=config_;
        auto& rules=candidate["rules"];
        const auto next=static_cast<size_t>(static_cast<std::ptrdiff_t>(index)+direction);
        std::swap(rules[index],rules[next]);
        commit(std::move(candidate),std::forward<Validator>(validate));return next;
    }
    template<typename Validator>
    void setDefault(const Json& action,Validator&& validate){
        Json candidate=config_; candidate["default_action"]=action;
        commit(std::move(candidate),std::forward<Validator>(validate));
    }
};
}
