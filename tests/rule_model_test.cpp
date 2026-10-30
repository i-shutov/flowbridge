#include <cassert>
#include <iostream>
#include <stdexcept>
#include "../native/windows/rule_model.hpp"
using namespace rule_editor;
static const char* sample = R"({"version":1,"listen":"127.0.0.1:1081","proxies":[{"id":"ssh","kind":"socks5","endpoint":{"host":"127.0.0.1","port":1080},"username":null,"password_env":null}],"chains":[],"rules":[],"default_action":{"type":"proxy","id":"ssh"},"connect_timeout_ms":10000,"handshake_timeout_ms":10000,"idle_timeout_ms":300000,"max_connections":512,"remote_dns_via_ssh":true})";
void run() {
    auto original=Json::parse(sample);
    Model model(original);
    auto strict=[](const std::string& serialized){auto cfg=Json::parse(serialized);if(cfg.at("rules").size()>4096)throw std::runtime_error("too many rules");for(const auto& r:cfg.at("rules")){if(r.at("id").get<std::string>().empty())throw std::runtime_error("empty ID");}};
    assert(model.size()==0);
    auto index=model.add(strict);
    assert(index==0&&!model.rule(0).at("enabled").get<bool>());
    auto fields=toFields(model.rule(0));
    fields.enabled=true; fields.id="movies";fields.hosts="*.example.net; HOST.example";fields.ports="80; 443; 8000-8020";
    fields.applications="C:\\Apps\\Player.exe";fields.networks="10.0.0.0/8";
    fields.action={{"type","proxy"},{"id","ssh"}};
    model.update(0,fields,strict);
    assert(model.rule(0).at("hosts").size()==2);
    assert(model.rule(0).at("ports").size()==3);
    assert(toFields(model.rule(0)).ports=="80; 443; 8000-8020");
    auto before=model.config().dump();
    fields.ports="65536";
    bool failed=false;try{model.update(0,fields,strict);}catch(...){failed=true;}
    assert(failed&&model.config().dump()==before);
    fields.ports="444-333";
    failed=false;try{model.update(0,fields,strict);}catch(...){failed=true;}
    assert(failed&&model.config().dump()==before);
    fields.ports="443";
    fields.id="";
    failed=false;try{model.update(0,fields,strict);}catch(...){failed=true;}
    assert(failed&&model.config().dump()==before);
    auto copied=model.duplicate(0,strict);
    assert(copied==1&&model.size()==2&&!model.rule(1).at("enabled").get<bool>());
    assert(model.rule(0).at("id")!=model.rule(1).at("id"));
    assert(model.move(1,-1,strict)==0);
    assert(model.rule(0).at("enabled")==false);
    model.setDefault({{"type","block"}},strict);
    assert(model.config().at("default_action").at("type")=="block");
    model.erase(0,strict);assert(model.size()==1);
    assert(model.config().at("listen")==original.at("listen"));
    assert(model.config().at("remote_dns_via_ssh")==true);
    assert(model.config().at("proxies")==original.at("proxies"));
    assert(choices(model.config()).size()==3);
}
int main(){run();std::cout<<"PASS native rule editor model: strict atomic edits, move, copy, ranges, default and profile preservation\n";}
