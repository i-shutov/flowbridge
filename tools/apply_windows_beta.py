from pathlib import Path

def edit(path,old,new):
    p=Path(path);s=p.read_text(encoding='utf-8')
    if s.count(old)!=1:raise RuntimeError(f'{path}: match count {s.count(old)} for {old[:100]!r}')
    p.write_text(s.replace(old,new),encoding='utf-8')

p='native/windows/native_ipc.hpp'
edit(p,'    Json last_=Json::object();ULONGLONG started_=0,observed_=0;','    Json last_=Json::object();ULONGLONG started_=0,observed_=0;bool verified_=false;')
edit(p,'        close(process_);close(pipe_);','        close(process_);close(pipe_);verified_=false;')
edit(p,'        if(!std::filesystem::equivalent(helper.parent_path(),trusted))throw std::runtime_error("Native mode requires the protected Program Files\\\\FlowBridgeBeta installation");','''#ifndef FLOWBRIDGE_IPC_TEST
        if(!std::filesystem::equivalent(helper.parent_path(),trusted))throw std::runtime_error("Native mode requires the protected Program Files\\\\FlowBridgeBeta installation");
#endif''')
edit(p,'            if(client!=GetProcessId(process_))throw std::runtime_error("Unexpected native pipe client");\n            Json message;','''            if(client!=GetProcessId(process_))throw std::runtime_error("Unexpected native pipe client");
            verified_=true;
        }
        if(verified_) {
            Json message;''')
edit(p,'        Json final=last_;cleanup();','''        try{poll(false);}catch(...){}
        DWORD exitCode=1;GetExitCodeProcess(process_,&exitCode);
        Json final=last_;cleanup();
        if(exitCode && !final.contains("error"))throw std::runtime_error("Native helper exited unsuccessfully; restoration not confirmed ("+std::to_string(exitCode)+")");''')

p='native/windows/main.cpp'
edit(p,'            result.release();if(action==-1)return;','            bool quit=result->exit;result.release();if(quit)return;')
edit(p,'                if(action==-1)result->exit=false;','''                if(action==-1)result->exit=false;
                const bool failedNativeStart=nativeWanted&&waiting;''')
edit(p,'if(managedActive&&(waiting||action==Start)){','if(managedActive&&!capture.alive()&&(waiting||action==Start||failedNativeStart)){')

p='native/windows/wfp/service.cpp'
edit(p,'void run() {','''void run() {
    HANDLE instance=CreateMutexW(nullptr,FALSE,L"Global\\\\FlowBridge.NativeCapture.Beta");
    if(!instance)throw std::runtime_error("Cannot acquire native capture lifetime guard");
    const DWORD previous=GetLastError();
    struct InstanceGuard{HANDLE handle;~InstanceGuard(){CloseHandle(handle);}} instanceGuard{instance};
    if(previous==ERROR_ALREADY_EXISTS)throw std::runtime_error("Another native capture helper is already active");''')

p='native/windows/wfp/dns_policy.ps1'
edit(p,'[string]$Rule.Namespace[0]', '[string](@($Rule.Namespace))[0]')
edit(p,'[string]$Rule.NameServers[0]', '[string](@($Rule.NameServers))[0]')

p='tests/native_dns_integration.py'
s=Path(p).read_text(encoding='utf-8');a=s.index('    kind = struct.unpack(\'!H\', question[-4:-2])[0]');b=s.index('\n\n\nclass Server',a)
s=s[:a]+'''    cursor = 12
    while question[cursor]:
        length = question[cursor]
        require(length <= 63 and cursor + length + 1 < len(question), 'Malformed fixture question')
        cursor += length + 1
    end = cursor + 5
    kind = struct.unpack('!H', question[cursor+1:cursor+3])[0]
    payload = socket.inet_pton(socket.AF_INET6, '2001:db8::123') if kind == 28 else socket.inet_aton('192.0.2.123')
    return struct.pack('!6H', ident ^ (1 if ident == 0xbeef else 0), 0x8180, 1, 1, 0, 0) + question[12:end] + b'\\xc0\\x0c' + struct.pack('!HHIH', kind, 1, 30, len(payload)) + payload
'''+s[b:];Path(p).write_text(s,encoding='utf-8')
print('Native lifetime, stop error propagation and DNS fixture checks applied')
