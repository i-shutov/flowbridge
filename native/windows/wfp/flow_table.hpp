#pragma once
#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <stdexcept>
#include "nlohmann/json.hpp"

// Display-only bounded registry. Source identity is supplied by the verified
// kernel redirect context, never by this table or by a reverse DNS guess.
class NativeFlowTable {
public:
    struct Row {
        uint64_t id=0,pid=0;
        unsigned port=0;
        std::string application,host,rule="pending",action="pending",state="connecting",error;
        std::atomic<uint64_t> bytesUp{0},bytesDown{0};
    };
private:
    mutable std::mutex mutex_;
    std::map<uint64_t,std::shared_ptr<Row>> active_;
    std::deque<std::shared_ptr<Row>> history_;
    static std::string bounded(std::string value,size_t limit=512){
        if(value.size()>limit){while(limit>0&&(static_cast<unsigned char>(value[limit])&0xc0)==0x80)--limit;value.resize(limit);}return value;
    }
    static nlohmann::json value(const std::shared_ptr<Row>& row){
        return {{"id",row->id},{"application",row->application},{"pid",row->pid},{"host",row->host},{"port",row->port},
            {"rule",row->rule},{"action",row->action},{"state",row->state},
            {"bytes_up",row->bytesUp.load()},{"bytes_down",row->bytesDown.load()},
            {"error",row->error.empty()?nlohmann::json():nlohmann::json(row->error)}};
    }
public:
    std::shared_ptr<Row> begin(uint64_t id,uint64_t pid,std::string app,std::string host,unsigned port){
        std::lock_guard<std::mutex> guard(mutex_);
        if(!id||active_.size()>=128||active_.count(id))throw std::runtime_error("Native flow display capacity or identity conflict");
        auto row=std::make_shared<Row>();row->id=id;row->pid=pid;row->application=bounded(std::move(app));row->host=bounded(std::move(host),256);row->port=port;
        active_.emplace(id,row);return row;
    }
    void connected(const std::shared_ptr<Row>& row,const nlohmann::json& decision){
        if(!row)return;std::lock_guard<std::mutex> guard(mutex_);
        auto rule=decision.value("rule_id",nlohmann::json());row->rule=rule.is_string()?bounded(rule.get<std::string>()):"default";
        const auto& action=decision.at("action");row->action=bounded(action.at("type").get<std::string>());
        if(action.contains("id")&&action["id"].is_string())row->action+=":"+bounded(action["id"].get<std::string>(),64);
        row->state="active";
    }
    void finish(const std::shared_ptr<Row>& row,std::string error={}) noexcept {
        if(!row)return;
        try{std::lock_guard<std::mutex> guard(mutex_);if(!active_.erase(row->id))return;
            row->state=error.empty()?"completed":"failed";row->error=bounded(std::move(error));
            history_.push_front(row);while(history_.size()>96)history_.pop_back();
        }catch(...){}
    }
    nlohmann::json snapshot()const{
        std::lock_guard<std::mutex> guard(mutex_);auto result=nlohmann::json::array();
        for(const auto& entry:active_)result.push_back(value(entry.second));
        for(const auto& row:history_)result.push_back(value(row));return result;
    }
};
