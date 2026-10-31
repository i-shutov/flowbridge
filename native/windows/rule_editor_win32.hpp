#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>
#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include "rule_model.hpp"
#include "flowbridge.h"

// Real, modal native Win32 rule-editor UI; no WebView, Javascript or shell.
// Save returns a DRAFT. The desktop's existing Apply path performs the
// active-engine reload, rather than changing routing under an untested dialog.
namespace rule_editor {
constexpr wchar_t WindowClass[]=L"FlowBridgeNativeRulesV1";
constexpr int List=6100, Id=6101, Applications=6102, Hosts=6103,
    Networks=6104, Ports=6105, Action=6106, Enabled=6107,
    Add=6108, Duplicate=6109, Remove=6110, Up=6111, Down=6112,
    SaveRule=6113, DefaultAction=6114, SaveDefault=6115,
    Accept=6116, Cancel=6117, Message=6118;
inline std::wstring wide(const std::string& input){
    if(input.empty())return {};
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),nullptr,0);
    if(!n)throw std::runtime_error("Правило содержит некорректную кодировку UTF-8.");
    std::wstring out(n,0);
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),out.data(),n);
    return out;
}
inline std::string utf8(HWND control){
    auto n=GetWindowTextLengthW(control);
    std::wstring value(n+1,L'\0');
    if(!GetWindowTextW(control,value.data(),n+1)&&n)throw std::runtime_error("Не удалось прочитать поле правила.");
    value.resize(n);
    if(value.empty())return {};
    auto bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),n,nullptr,0,nullptr,nullptr);
    if(!bytes)throw std::runtime_error("Некорректные символы в поле правила.");
    std::string result(bytes,0);
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),n,result.data(),bytes,nullptr,nullptr);
    return result;
}
inline void set(HWND h,const std::string& text){
    auto s=wide(text);
    SetWindowTextW(h,s.c_str());
}
inline void verify(const std::string& serialized){
    if(serialized.size()>1024*1024)throw std::invalid_argument("Профиль превышает 1 МиБ.");
    auto* raw=fb_validate_json(serialized.c_str());
    if(!raw)throw std::runtime_error("Движок не ответил на проверку правила.");
    std::unique_ptr<char,decltype(&fb_string_free)> owned(raw,fb_string_free);
    auto result=Json::parse(raw);
    if(!result.value("ok",false))throw std::runtime_error(result.value("error",std::string("Недопустимое правило.")));
}

class Dialog {
    HWND parent_{};
    HWND window_{};
    Model model_;
    std::vector<Json> routes_;
    int current_=-1;
    bool loading_=false;
    bool accepted_=false;
    std::optional<std::string> answer_;
    HWND get(int id)const{return GetDlgItem(window_,id);}
    void message(const std::string& text){set(get(Message),text);}
    static void check(bool ok,const char* text){if(!ok)throw std::runtime_error(text);}
    HWND create(const wchar_t* cls,const wchar_t* label,DWORD style,int id){
        auto c=CreateWindowExW(0,cls,label,WS_CHILD|WS_VISIBLE|style,0,0,20,20,
                               window_,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                               GetModuleHandleW(nullptr),nullptr);
        check(c!=nullptr,"Не удалось создать элемент визуального редактора.");
        SendMessageW(c,WM_SETFONT,reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),TRUE);
        return c;
    }
    void controls(){
        create(L"STATIC",L"Правила сверху вниз · первое совпадение",0,6200);
        create(L"LISTBOX",L"",WS_BORDER|WS_VSCROLL|LBS_NOTIFY|WS_TABSTOP,List);
        create(L"STATIC",L"ID правила",0,6201);
        create(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,Id);
        create(L"STATIC",L"Приложения (через ; · только проверенная identity)",0,6202);
        create(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,Applications);
        create(L"STATIC",L"Хосты / wildcard * и ? (через ;)",0,6203);
        create(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,Hosts);
        create(L"STATIC",L"Сети IPv4 / IPv6 CIDR (через ;)",0,6204);
        create(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,Networks);
        create(L"STATIC",L"Порты 443; 8000-8010 (пусто = любые)",0,6205);
        create(L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,Ports);
        create(L"STATIC",L"Действие",0,6206);
        create(L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP|WS_VSCROLL,Action);
        create(L"BUTTON",L"Правило включено",BS_AUTOCHECKBOX|WS_TABSTOP,Enabled);
        create(L"BUTTON",L"Проверить и сохранить правило",WS_TABSTOP,SaveRule);
        create(L"BUTTON",L"Добавить",WS_TABSTOP,Add);
        create(L"BUTTON",L"Копировать",WS_TABSTOP,Duplicate);
        create(L"BUTTON",L"Удалить",WS_TABSTOP,Remove);
        create(L"BUTTON",L"Выше ↑",WS_TABSTOP,Up);
        create(L"BUTTON",L"Ниже ↓",WS_TABSTOP,Down);
        create(L"STATIC",L"Если ни одно правило не подошло:",0,6207);
        create(L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP|WS_VSCROLL,DefaultAction);
        create(L"BUTTON",L"Назначить",WS_TABSTOP,SaveDefault);
        create(L"STATIC",L"",0,Message);
        create(L"BUTTON",L"Сохранить черновик",WS_TABSTOP,Accept);
        create(L"BUTTON",L"Отмена",WS_TABSTOP,Cancel);
        for(int id:{Id,Applications,Hosts,Networks,Ports})
            SendMessageW(get(id),EM_SETLIMITTEXT,8192,0);
        routes_=choices(model_.config());
        for(const auto& option:routes_){
            auto label=wide(actionName(option));
            SendMessageW(get(Action),CB_ADDSTRING,0,reinterpret_cast<LPARAM>(label.c_str()));
            SendMessageW(get(DefaultAction),CB_ADDSTRING,0,reinterpret_cast<LPARAM>(label.c_str()));
        }
        selectAction(DefaultAction,model_.config().at("default_action"));
        refresh(0);
        message("Черновик: изменения маршрута вступят в силу только после «Применить профиль».");
    }
    void layout(){
        if(!get(List))return;
        RECT rect{};GetClientRect(window_,&rect);
        int w=rect.right,h=rect.bottom,left=std::max(270,w*38/100),right=left+32,rightW=w-right-15;
        auto mv=[&](int id,int x,int y,int width,int height){MoveWindow(get(id),x,y,std::max(1,width),std::max(1,height),TRUE);};
        mv(6200,16,16,left-20,26);
        mv(List,16,48,left-20,std::max(210,h-178));
        const int buttonY=h-116;
        int bw=(left-44)/3;
        mv(Add,16,buttonY,bw,31);mv(Duplicate,24+bw,buttonY,bw,31);mv(Remove,32+2*bw,buttonY,bw,31);
        mv(Up,16,buttonY+36,(left-30)/2,30);mv(Down,24+(left-30)/2,buttonY+36,(left-30)/2,30);
        for(int i=0;i<5;++i){
            int label=6201+i,field=Id+i,y=18+i*52;
            mv(label,right,y,rightW,21);mv(field,right,y+21,rightW,28);
        }
        mv(6206,right,278,rightW,21);mv(Action,right,300,rightW,190);
        mv(Enabled,right,335,rightW,24);
        mv(SaveRule,right,364,std::min(270,rightW),32);
        mv(6207,right,406,rightW,22);
        mv(DefaultAction,right,429,rightW-124,190);mv(SaveDefault,right+rightW-116,429,116,28);
        mv(Message,right,464,rightW,std::max(25,h-529));
        mv(Accept,w-364,h-48,190,36);mv(Cancel,w-164,h-48,150,36);
    }
    size_t actionIndex(const Json& value)const{
        for(size_t i=0;i<routes_.size();++i)if(routes_[i]==value)return i;
        throw std::runtime_error("Действие отсутствует в списке прокси/цепочек.");
    }
    void selectAction(int control,const Json& value){
        SendMessageW(get(control),CB_SETCURSEL,actionIndex(value),0);
    }
    Json chosenAction(int control)const{
        auto index=SendMessageW(get(control),CB_GETCURSEL,0,0);
        if(index==CB_ERR||static_cast<size_t>(index)>=routes_.size())throw std::runtime_error("Выберите допустимое действие.");
        return routes_.at(static_cast<size_t>(index));
    }
    Fields fields()const{
        Fields out;
        out.id=utf8(get(Id));out.applications=utf8(get(Applications));out.hosts=utf8(get(Hosts));
        out.networks=utf8(get(Networks));out.ports=utf8(get(Ports));
        out.enabled=SendMessageW(get(Enabled),BM_GETCHECK,0,0)==BST_CHECKED;
        out.action=chosenAction(Action);
        return out;
    }
    void load(size_t index){
        loading_=true;
        const auto value=toFields(model_.rule(index));
        set(get(Id),value.id);set(get(Applications),value.applications);
        set(get(Hosts),value.hosts);set(get(Networks),value.networks);set(get(Ports),value.ports);
        SendMessageW(get(Enabled),BM_SETCHECK,value.enabled?BST_CHECKED:BST_UNCHECKED,0);
        selectAction(Action,value.action);
        current_=static_cast<int>(index);
        loading_=false;
    }
    void refresh(size_t selected){
        loading_=true;
        SendMessageW(get(List),LB_RESETCONTENT,0,0);
        for(size_t i=0;i<model_.size();++i){
            const auto& rule=model_.rule(i);
            auto name=(rule.at("enabled").get<bool>()?"● ":"○ ")+rule.at("id").get<std::string>()+
                       " · "+actionName(rule.at("action"));
            auto label=wide(name);
            SendMessageW(get(List),LB_ADDSTRING,0,reinterpret_cast<LPARAM>(label.c_str()));
        }
        loading_=false;
        if(model_.size()==0){
            current_=-1;
            for(int id:{Id,Applications,Hosts,Networks,Ports})SetWindowTextW(get(id),L"");
            SendMessageW(get(Enabled),BM_SETCHECK,BST_UNCHECKED,0);
            for(int id:{Id,Applications,Hosts,Networks,Ports,Action,Enabled,SaveRule,Duplicate,Remove,Up,Down})EnableWindow(get(id),FALSE);
        }else{
            for(int id:{Id,Applications,Hosts,Networks,Ports,Action,Enabled,SaveRule,Duplicate,Remove,Up,Down})EnableWindow(get(id),TRUE);
            selected=std::min(selected,model_.size()-1);
            SendMessageW(get(List),LB_SETCURSEL,selected,0);
            load(selected);
            EnableWindow(get(Up),selected>0);
            EnableWindow(get(Down),selected+1<model_.size());
        }
    }
    void store(){
        if(current_<0)return;
        const auto edited=fields();
        model_.update(static_cast<size_t>(current_),edited,verify);
    }
    void handle(int id, int event){
        if(loading_)return;
        try{
            if(id==List&&event==LBN_SELCHANGE){
                int next=static_cast<int>(SendMessageW(get(List),LB_GETCURSEL,0,0));
                if(next<0||next==current_)return;
                int old=current_;
                try{store();}catch(...){SendMessageW(get(List),LB_SETCURSEL,old,0);throw;}
                refresh(static_cast<size_t>(next));
                return;
            }
            if(event!=BN_CLICKED)return;
            if(id==Cancel){DestroyWindow(window_);return;}
            if(id==SaveRule){store();refresh(static_cast<size_t>(std::max(0,current_)));message("Правило проверено Rust-движком; черновик ещё не применён.");return;}
            if(id==Accept){
                store();model_.setDefault(chosenAction(DefaultAction),verify);
                answer_=model_.config().dump(2);
                accepted_=true;DestroyWindow(window_);return;
            }
            if(id==SaveDefault){store();model_.setDefault(chosenAction(DefaultAction),verify);
                refresh(static_cast<size_t>(std::max(0,current_)));message("Действие по умолчанию проверено.");return;}
            if(id==Add){store();auto index=model_.add(verify);refresh(index);
                message("Новое правило выключено для защиты от случайного перехвата всего трафика.");return;}
            if(id==Duplicate&&current_>=0){store();auto index=model_.duplicate(current_,verify);refresh(index);
                message("Копия выключена до явного включения.");return;}
            if(id==Remove&&current_>=0){store();auto index=static_cast<size_t>(current_);
                model_.erase(index,verify);refresh(index);message("Правило удалено только из черновика.");return;}
            if((id==Up||id==Down)&&current_>=0){store();auto index=model_.move(current_,id==Up?-1:1,verify);
                refresh(index);message("Порядок правил изменён; первое совпадение имеет приоритет.");return;}
        }catch(const std::exception& error){
            message(std::string("Ошибка: ")+error.what());MessageBeep(MB_ICONWARNING);
        }
    }
    static LRESULT CALLBACK proc(HWND h,UINT msg,WPARAM w,LPARAM l){
        Dialog* self=reinterpret_cast<Dialog*>(GetWindowLongPtrW(h,GWLP_USERDATA));
        if(msg==WM_NCCREATE){
            auto* cs=reinterpret_cast<CREATESTRUCTW*>(l);
            self=static_cast<Dialog*>(cs->lpCreateParams);
            SetWindowLongPtrW(h,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));
            self->window_=h;
        }
        if(!self)return DefWindowProcW(h,msg,w,l);
        switch(msg){
        case WM_CREATE:
            try{self->controls();self->layout();}
            catch(const std::exception& ex){MessageBoxW(h,wide(ex.what()).c_str(),L"Ошибка редактора",MB_ICONERROR);return -1;}
            return 0;
        case WM_GETMINMAXINFO:{auto* info=reinterpret_cast<MINMAXINFO*>(l);info->ptMinTrackSize={820,570};return 0;}
        case WM_SIZE:self->layout();return 0;
        case WM_COMMAND:self->handle(LOWORD(w),HIWORD(w));return 0;
        case WM_CLOSE:DestroyWindow(h);return 0;
        case WM_DESTROY:self->window_=nullptr;return 0;
        }
        return DefWindowProcW(h,msg,w,l);
    }
public:
    Dialog(HWND parent,const std::string& serialized):parent_(parent),model_(Json::parse(serialized)){
        verify(serialized);routes_=choices(model_.config());
    }
    std::optional<std::string> run(){
        WNDCLASSW cls{};cls.lpfnWndProc=proc;cls.hInstance=GetModuleHandleW(nullptr);
        cls.lpszClassName=WindowClass;cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);
        cls.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_BTNFACE+1);
        if(!RegisterClassW(&cls)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)
            throw std::runtime_error("Не удалось зарегистрировать окно правил.");
        RECT area{};SystemParametersInfoW(SPI_GETWORKAREA,0,&area,0);
        int width=std::min(920,static_cast<int>(area.right-area.left-24));
        int height=std::min(655,static_cast<int>(area.bottom-area.top-24));
        if(width<820||height<570)throw std::runtime_error("Недостаточно места для редактора при текущем DPI.");
        auto x=area.left+(area.right-area.left-width)/2,y=area.top+(area.bottom-area.top-height)/2;
        window_=CreateWindowExW(WS_EX_DLGMODALFRAME|WS_EX_CONTROLPARENT,WindowClass,
                  L"FlowBridge · визуальные правила маршрутизации",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_THICKFRAME|WS_CLIPCHILDREN,
                  x,y,width,height,parent_,nullptr,GetModuleHandleW(nullptr),this);
        if(!window_)throw std::runtime_error("Не удалось открыть визуальный редактор правил.");
        EnableWindow(parent_,FALSE);
        ShowWindow(window_,SW_SHOW);SetForegroundWindow(window_);
        MSG msg{};
        while(window_){
            BOOL status=GetMessageW(&msg,nullptr,0,0);
            if(status<=0){
                if(window_)DestroyWindow(window_);
                if(status==0)PostQuitMessage(static_cast<int>(msg.wParam));
                break;
            }
            if(!IsDialogMessageW(window_,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}
        }
        EnableWindow(parent_,TRUE);SetForegroundWindow(parent_);
        return accepted_?answer_:std::nullopt;
    }
};
inline std::optional<std::string> run(HWND parent,const std::string& profile){
    return Dialog(parent,profile).run();
}
}
