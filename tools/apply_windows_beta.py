from pathlib import Path

def edit(path,old,new):
 p=Path(path);s=p.read_text(encoding='utf-8')
 if s.count(old)!=1:raise RuntimeError(f'{path}: expected one match, got {s.count(old)}: {old[:80]!r}')
 p.write_text(s.replace(old,new),encoding='utf-8')

p='native/windows/main.cpp'
edit(p,'    for(const auto& pair:pages){bool visible=pair.second<0||pair.second==activePage;','''    for(const auto& pair:pages){bool visible=pair.second<0||pair.second==activePage;
        if(pair.second==11)visible=activePage==1&&!managed;
        if(pair.second==12)visible=activePage==1&&managed;''')
edit(p,'if(id==ManagedMode&&event==CBN_SELCHANGE){updateVisibility();layout();InvalidateRect(h,nullptr,TRUE);}',
 'if(id==ManagedMode&&event==CBN_SELCHANGE){updateVisibility();layout();showSsh(latestSshSnapshot,false);InvalidateRect(h,nullptr,TRUE);}')
edit(p,'if(ssh.is_null()){bool managed=', 'if(ssh.is_null()||ssh.empty()){bool managed=')
p='tests/windows_native_smoke.cpp'
edit(p,'need(IsWindowVisible(GetDlgItem(window,231))&&!IsWindowVisible(GetDlgItem(window,hostId)),"managed SSH mode visibility failed");','''need(IsWindowVisible(GetDlgItem(window,231))&&!IsWindowVisible(GetDlgItem(window,hostId)),"managed SSH mode visibility failed");
        for(int id:{2010,2011,2012,2013,2014,2015,2016,2017,2019,2020,243}){
            HWND label=GetDlgItem(window,id);
            need(IsWindowVisible(label)&&GetWindowTextLengthW(label)>0,"SSH field label or explanation is missing");
        }
        need(!IsWindowVisible(GetDlgItem(window,2000)),"External proxy label leaked into SSH layout");''')
# Capture's device-open failure is a deployment prerequisite, not a proxy error.
p='native/windows/wfp/capture.cpp'
s=Path(p).read_text(encoding='utf-8')
old='if(driver_==INVALID_HANDLE_VALUE) check(GetLastError(),"Open FlowBridge WFP device");'
if old not in s:
 import re
 matches=list(re.finditer(r'if\s*\(driver_\s*==\s*INVALID_HANDLE_VALUE\)[^\n]+',s))
 assert len(matches)==1, 'Driver open error line changed'
 old=matches[0].group(0)
new='''if(driver_==INVALID_HANDLE_VALUE) {
        DWORD error=GetLastError();
        throw std::runtime_error("Native interception unavailable: FlowBridgeWfp kernel driver is not loaded or access was refused (Windows error "+std::to_string(error)+"). This candidate does not install a driver. Use an authorized internal test machine with the matching signed driver. DNS and capture settings have not been enabled.");
    }'''
assert s.count(old)==1
Path(p).write_text(s.replace(old,new),encoding='utf-8')
print('SSH labels are visible and asserted; missing-driver activation failure is explicit before network changes')
