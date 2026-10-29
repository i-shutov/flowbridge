from pathlib import Path
source=Path('tools/native-flow-patch.py').read_text(encoding='utf-8')
old="edit(p,'offset+=static_cast<size_t>(n); last=GetTickCount64();','offset+=static_cast<size_t>(n); row->bytesUp.fetch_add(static_cast<uint64_t>(n)); last=GetTickCount64();',1)"
new="edit(p,'                    offset+=static_cast<size_t>(n); last=GetTickCount64();','                    offset+=static_cast<size_t>(n); row->bytesUp.fetch_add(static_cast<uint64_t>(n)); last=GetTickCount64();',1)"
assert source.count(old)==1
source=source.replace(old,new)
source=source.replace('status pressure\\n";', 'status pressure\\\\n";')
exec(compile(source,'tools/native-flow-patch.py','exec'))
p=Path('native/windows/main.cpp');s=p.read_text(encoding='utf-8')
a='pendingStart=false,tunnelReady=true;';assert s.count(a)==1
s=s.replace(a,'pendingStart=false,tunnelReady=true,captureUncertain=false;')
a='    bool native=status.value("transparent",false);';assert s.count(a)==1
s=s.replace(a,a+'\n    captureUncertain=status.value("uncertain",false);')
a='if(status.value("display_connections_omitted",0))text+=" | Часть строк скрыта лимитом отображения";';assert s.count(a)==1
s=s.replace(a,a+'\n    setText(GetDlgItem(window,Status),text);')
a='engineRunning&&tunnelReady?RGB(18,143,98)';assert s.count(a)==1
s=s.replace(a,'engineRunning&&tunnelReady&&!captureUncertain?RGB(18,143,98)')
p.write_text(s,encoding='utf-8')
print('Native per-flow identity, counters, selected-path filtering and bounded status prepared')
