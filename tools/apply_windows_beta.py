from pathlib import Path
p=Path('native/windows/CMakeLists.txt');s=p.read_text()
s+='''
if(FLOWBRIDGE_BUILD_NATIVE_TESTS)
  add_executable(FlowBridgeIPCSmoke ../../tests/windows_native_ipc.cpp)
  target_compile_definitions(FlowBridgeIPCSmoke PRIVATE FLOWBRIDGE_IPC_TEST)
  target_include_directories(FlowBridgeIPCSmoke PRIVATE ../../third_party)
  target_link_libraries(FlowBridgeIPCSmoke PRIVATE shell32 ole32 uuid user32 advapi32)
  if(MSVC)
    target_compile_options(FlowBridgeIPCSmoke PRIVATE /W4 /utf-8)
    set_property(TARGET FlowBridgeIPCSmoke PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  elseif(MINGW)
    target_link_options(FlowBridgeIPCSmoke PRIVATE -municode -static -static-libgcc -static-libstdc++)
  endif()
endif()
'''
p.write_text(s)
p=Path('tests/windows_dns_policy.py');s=p.read_text();s=s.replace('import time\n','import time\nimport tempfile\n')
a="        report['passed']=True";assert s.count(a)==1
s=s.replace(a,'''        abi.lib.fb_native_destroy(ident);ident=0
        # A separately owned listener lets us kill the exact process and verify
        # the independent rollback guardian rather than normal Stop cleanup.
        with tempfile.TemporaryDirectory(prefix='flowbridge-dns-crash-') as temporary:
            ready=Path(temporary)/'ready'
            code="import socket,time,sys,pathlib;u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('127.0.0.1',53));t=socket.socket();t.bind(('127.0.0.1',53));t.listen();pathlib.Path(sys.argv[1]).write_text('ready');time.sleep(120)"
            owner=subprocess.Popen([sys.executable,'-c',code,str(ready)])
            try:
                until(lambda:ready.exists() or owner.poll() is not None,10)
                require(owner.poll() is None and ready.exists(),'Crash-test listener failed to bind')
                policy('Enter',token,owner.pid)
                require(has_token(token),'Crash-test DNS rule was not installed')
                owner.kill();owner.wait(timeout=5)
                until(lambda:not has_token(token),30)
                require(baseline()==before,'Guardian changed adapter DNS')
            finally:
                if owner.poll() is None:owner.kill();owner.wait(timeout=5)
                policy('Exit',token,os.getpid())
        report['checks'].append('Independent guardian removes the exact owned DNS policy after its listener process is killed')
        report['passed']=True''')
p.write_text(s)
print('Actual IPC, native installer lifecycle and DNS guardian crash tests added')
