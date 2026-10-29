from pathlib import Path

def edit(path,old,new,count=1):
 p=Path(path);s=p.read_text(encoding='utf-8')
 if s.count(old)!=count:raise RuntimeError(f'{path}: expected {count}, got {s.count(old)} for {old[:90]!r}')
 p.write_text(s.replace(old,new),encoding='utf-8')

p='native/windows/wfp/capture.h'
edit(p,'bool remoteDns=false);','bool remoteDns=false, bool captureAll=true);')
p='native/windows/wfp/capture.cpp'
edit(p,'const std::vector<std::wstring>& quicApplications, bool remoteDns) {','const std::vector<std::wstring>& quicApplications, bool remoteDns, bool captureAll) {')
edit(p,'            check(FwpmFilterAdd0(engine_,&filter,nullptr,nullptr),"Add TCP filter");','''            if(captureAll)check(FwpmFilterAdd0(engine_,&filter,nullptr,nullptr),"Add TCP filter");
            else {
                if(quicApplications.empty())throw std::runtime_error("Selected application capture requires at least one executable path");
                for(const auto& path:quicApplications){
                    FWP_BYTE_BLOB* app=nullptr;check(FwpmGetAppIdFromFileName0(path.c_str(),&app),"Resolve selected capture executable");
                    FWPM_FILTER_CONDITION0 conditions[2]={tcp,{}};
                    conditions[1].fieldKey=FWPM_CONDITION_ALE_APP_ID;conditions[1].matchType=FWP_MATCH_EQUAL;
                    conditions[1].conditionValue.type=FWP_BYTE_BLOB_TYPE;conditions[1].conditionValue.byteBlob=app;
                    filter.numFilterConditions=2;filter.filterCondition=conditions;
                    DWORD result=FwpmFilterAdd0(engine_,&filter,nullptr,nullptr);
                    FwpmFreeMemory0(reinterpret_cast<void**>(&app));check(result,"Add selected executable TCP filter");
                }
                filter.numFilterConditions=1;filter.filterCondition=&tcp;
            }''')
p='native/windows/native_ipc.hpp'
edit(p,'inline bool send(HANDLE pipe,const Json& value) {','''inline Json boundedStatus(Json value) {
    // Preserve readiness and aggregate counters even under a large connection
    // history. Drop oldest display data, never silently lose every heartbeat.
    if(value.contains("native")&&value["native"].is_object()){
        auto& snapshot=value["native"];auto& events=snapshot["events"];auto& rows=snapshot["connections"];
        unsigned omittedEvents=0,omittedRows=0;
        while(value.dump().size()>MaxMessage-512){
            if(events.is_array()&&!events.empty()){events.erase(events.begin());++omittedEvents;}
            else if(rows.is_array()&&!rows.empty()){rows.erase(rows.end()-1);++omittedRows;}
            else throw std::runtime_error("Native aggregate status exceeds control-message limit");
        }
        if(omittedEvents||omittedRows){snapshot["status"]["display_events_omitted"]=omittedEvents;snapshot["status"]["display_connections_omitted"]=omittedRows;}
    }
    return value;
}
inline bool send(HANDLE pipe,const Json& value) {''')
edit(p,'if(pipe_)send(pipe_,value);','if(pipe_)send(pipe_,boundedStatus(value));')
edit(p,'    bool exists()const{return process_!=nullptr;}','    Json cached()const{return last_;}\n    bool exists()const{return process_!=nullptr;}')

p='native/windows/wfp/service.cpp'
edit(p,'#include "dns_policy.hpp"','#include "dns_policy.hpp"\n#include "flow_table.hpp"')
edit(p,'std::deque<Json> recent;','std::deque<Json> recent;\nNativeFlowTable flowTable;')
edit(p,'recent.push_back({{"level",event.contains("error")?"error":"info"},{"message",event.dump()}});','''auto message=event.dump();if(message.size()>1024){size_t end=1024;while(end>0&&(static_cast<unsigned char>(message[end])&0xc0)==0x80)--end;message.resize(end);message+="…";}
            recent.push_back({{"level",event.contains("error")?"error":"info"},{"message",std::move(message)}});''')
edit(p,'void relay(SOCKET socket,uint64_t id,uint64_t idleMs) {','bool relay(SOCKET socket,uint64_t id,uint64_t idleMs,const std::shared_ptr<NativeFlowTable::Row>& row) {')
edit(p,'offset+=static_cast<size_t>(n); last=GetTickCount64();','offset+=static_cast<size_t>(n); row->bytesUp.fetch_add(static_cast<uint64_t>(n)); last=GetTickCount64();',1)
# The download direction uses different indentation but the same text after the
# upload replacement, so it must be patched using the complete remaining line.
edit(p,'                offset+=static_cast<size_t>(n); last=GetTickCount64();','                offset+=static_cast<size_t>(n); row->bytesDown.fetch_add(static_cast<uint64_t>(n)); last=GetTickCount64();')
edit(p,'    upload.join();\n}', '    upload.join();\n    return !failed.load()&&!stopping.load()&&GetTickCount64()-last.load()<=idleMs;\n}')
edit(p,'    Socket socket(raw); FbRedirectContext context{};','    Socket socket(raw); FbRedirectContext context{};std::shared_ptr<NativeFlowTable::Row> row;')
edit(p,'        // Core copies records and sets them on EVERY outbound socket before','''        row=flowTable.begin(context.flow_id,context.original_process_id,application,address,ntohs(context.destination_port_be));
        // Core copies records and sets them on EVERY outbound socket before''')
edit(p,'        if(stopping) return;','        if(stopping){flowTable.finish(row,"Stopped before stream forwarding");return;}\n        flowTable.connected(row,result.at("decision"));')
edit(p,'        relay(raw,stream.id,idleMs);','        const bool clean=relay(raw,stream.id,idleMs,row);\n        flowTable.finish(row,clean?"":"Stream stopped, failed or reached idle deadline");')
edit(p,'    } catch (const std::exception& e) {log({{"event","rejected"},{"flow_id",context.flow_id},{"error",e.what()}});}','    } catch (const std::exception& e) {flowTable.finish(row,e.what());log({{"event","rejected"},{"flow_id",context.flow_id},{"error",e.what()}});}')
edit(p,'    catch (...) {log({{"event","rejected"},{"error","Unexpected native failure"}});}','    catch (...) {flowTable.finish(row,"Unexpected native failure");log({{"event","rejected"},{"error","Unexpected native failure"}});}')
edit(p,'    uiState("starting");','''    const bool captureAll=nativeOptions.value("capture_all_applications",true);
    nativeOptions.erase("capture_all_applications");
    uiState("starting");''')
edit(p,'capture.start(p4,p6,bypassPaths,quicApplications,nativeOptions.contains("dns")&&!nativeOptions["dns"].is_null());','capture.start(p4,p6,bypassPaths,quicApplications,nativeOptions.contains("dns")&&!nativeOptions["dns"].is_null(),captureAll);')
edit(p,'                uiState("ready",report);lastSnapshot=GetTickCount64();','                report["connections"]=flowTable.snapshot();\n                uiState("ready",report);lastSnapshot=GetTickCount64();')

p='native/windows/main.cpp'
edit(p,'        nativeOptions["quic_applications"]=pendingOptions.at("selected_applications");','''        nativeOptions["quic_applications"]=pendingOptions.at("selected_applications");
        nativeOptions["capture_all_applications"]=pendingOptions.value("block_other_applications",false);''')
edit(p,'                try{if(engine)result->snapshot=response(fb_engine_snapshot_json(engine));}catch(...){}','''                try{
                    if(capture.alive()){
                        result->snapshot=capture.cached().value("native",Json{{"status",{{"running",true},{"transparent",true}}}});
                        result->snapshot["status"]["running"]=true;result->snapshot["status"]["uncertain"]=true;
                    }else if(engine)result->snapshot=response(fb_engine_snapshot_json(engine));
                }catch(...){}''')
edit(p,'    bool native=status.value("transparent",false);','    bool native=status.value("transparent",false);\n    if(status.value("display_connections_omitted",0))text+=" | Часть строк скрыта лимитом отображения";')
edit(p,'    setText(GetDlgItem(window,Mode),native?', '    if(status.value("uncertain",false))setText(GetDlgItem(window,Badge),"●  Состояние перехвата не подтверждено — смотрите ошибку");\n    setText(GetDlgItem(window,Mode),native?')
edit(p,'display(connection,"id"), display(connection,"host")','display(connection,"id"), display(connection,"application"), display(connection,"host")')
edit(p,'for(int col=1;col<7;++col) ListView_SetItemText','for(int col=1;col<8;++col) ListView_SetItemText')
edit(p,'const wchar_t* titles[]={L"ID",L"Назначение",L"Правило",L"Маршрут",L"Состояние",L"↑ / ↓, байт",L"Ошибка"};int widths[]={48,190,145,130,130,135,180};for(int i=0;i<7;++i)', 'const wchar_t* titles[]={L"ID",L"Приложение",L"Назначение",L"Правило",L"Маршрут",L"Состояние",L"↑ / ↓, байт",L"Ошибка"};int widths[]={48,140,190,145,130,130,135,180};for(int i=0;i<8;++i)')
edit(p,'Сопоставление по имени EXE, без проверки издателя','WFP ограничен выбранными путями EXE; издатель не проверяется')

p='tests/windows_native_ipc.cpp'
edit(p,'#include <iostream>','#include <iostream>\n#include "../native/windows/wfp/flow_table.hpp"')
edit(p,'        auto dir=native_ipc::executableDirectory();','''        NativeFlowTable table;std::vector<std::shared_ptr<NativeFlowTable::Row>> rows;
        for(uint64_t i=1;i<=128;++i)rows.push_back(table.begin(i,100+i,"fixture.exe","192.0.2.1",443));
        bool full=false;try{table.begin(129,1,"extra.exe","192.0.2.1",443);}catch(...){full=true;}require(full,"Native flow table is unbounded");
        table.connected(rows[0],{{"rule_id","selected"},{"action",{{"type","proxy"},{"id","ssh"}}}});
        std::vector<std::thread> counters;for(unsigned i=0;i<4;++i)counters.emplace_back([&]{for(unsigned n=0;n<10000;++n)rows[0]->bytesUp.fetch_add(1);});
        for(auto& thread:counters)thread.join();
        require(table.snapshot()[0]["bytes_up"]==40000&&table.snapshot()[0]["application"]=="fixture.exe","Native per-flow counters or identity changed");
        for(const auto& row:rows)table.finish(row);
        require(table.snapshot().size()==96,"Native history bound was not preserved");
        Json oversized={{"state","ready"},{"native",{{"status",{{"running",true},{"active",128}}},{"connections",table.snapshot()},{"events",Json::array()}}}};
        for(unsigned i=0;i<200;++i)oversized["native"]["events"].push_back({{"message",std::string(2048,'x')}});
        auto bounded=native_ipc::boundedStatus(oversized);
        require(bounded.dump().size()<=native_ipc::MaxMessage&&bounded["native"]["status"]["active"]==128,"Status pressure lost readiness/counters or exceeded IPC bound");
        require(bounded["native"]["status"]["display_events_omitted"].get<unsigned>()>0,"Display truncation was not disclosed");
        std::cout<<"PASS: bounded native per-flow history, concurrent counters and oversized status pressure\n";
        auto dir=native_ipc::executableDirectory();''')
print('Selected-path TCP capture, live native flow rows and bounded status delivery integrated')
