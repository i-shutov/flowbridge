#!/usr/bin/env python3
"""Real Windows DNS-client/NRPT integration on a disposable hosted runner.
Only the reserved only-on-ssh.test FQDN is redirected. Never run on a workstation.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import tempfile
import uuid
from native_dns_integration import ABI, configure, Server, Resolver, ForwardSocks, start, stop
from ssh_real_integration import require, until, free_port

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'native/windows/wfp/dns_policy.ps1'
PS=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'

def ps(*args, command=None):
    invocation=[str(PS),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass']
    invocation+=['-Command',command] if command is not None else ['-File',str(SCRIPT),*map(str,args)]
    result=subprocess.run(invocation,stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding='utf-8',errors='replace',timeout=45)
    require(result.returncode==0, 'PowerShell transaction failed: '+result.stdout+' '+result.stderr)
    return result.stdout.strip()

def policy(action,token,owner=0):
    return ps('-Action',action,'-Token',token,'-OwnerProcessId',owner,'-Namespace','only-on-ssh.test')

def baseline():
    return ps(command="Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Compress")

def rules():
    return json.loads(ps(command="@(@(Get-DnsClientNrptRule) | ForEach-Object { $_.DisplayName }) | ConvertTo-Json -Compress -AsArray"))

def has_token(token):
    output=ps(command="[int]@((Get-DnsClientNrptRule) | Where-Object DisplayName -eq 'FlowBridge beta DNS "+token+"').Count")
    return output.strip()!='0'

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    require(sys.platform=='win32' and os.environ.get('GITHUB_ACTIONS')=='true','Disposable Windows GitHub runner required')
    require(ctypes.windll.shell32.IsUserAnAdmin()!=0,'Elevated runner required')
    os.environ['FLOWBRIDGE_ISOLATED_DNS_QA']='1'
    before=baseline();token=str(uuid.uuid4());ident=0
    report={'passed':False,'scope':'only-on-ssh.test','kernel_capture_tested':False,'checks':[]}
    abi=ABI(ROOT/'target/debug/flowbridge_ffi.dll');configure(abi)
    resolver=Server(('127.0.0.1',0),Resolver);rt=start(resolver)
    proxy=Server(('127.0.0.1',0),ForwardSocks);proxy.resolver_port=resolver.server_address[1];proxy.reject=False;pt=start(proxy)
    endpoint={'host':'127.0.0.1','port':proxy.server_address[1]}
    profile={'version':1,'listen':f'127.0.0.1:{free_port()}',
        'proxies':[{'id':'ssh','kind':'socks5','endpoint':endpoint}],'chains':[],'rules':[],
        'default_action':{'type':'block'},'connect_timeout_ms':1000,'handshake_timeout_ms':1000,
        'idle_timeout_ms':60000,'max_connections':32}
    options={'managed_endpoint':endpoint,'ready':True,'ready_lease_ms':10000,
        'dns':{'resolver':{'host':'127.0.0.1','port':resolver.server_address[1]},'timeout_ms':2000}}
    try:
        # Both listening sockets are owned by this process and verified by PS.
        ident=abi.call('fb_native_create_json',profile,options)['session_id']
        abi.call('fb_native_dns_start_json',ident,{'listen':'127.0.0.1:53'})
        policy('Enter',token,os.getpid())
        abi.call('fb_native_set_gate_json',ident,{'ready':True})
        addresses={row[4][0] for row in socket.getaddrinfo('only-on-ssh.test',443,type=socket.SOCK_STREAM)}
        require('192.0.2.123' in addresses,'Windows resolver did not use the owned SSH DNS path')
        require(resolver.requests>0,'No query reached the simulated remote resolver')
        report['checks'].append('Actual Windows getaddrinfo follows the owned NRPT rule to native UDP/TCP DNS')
        policy('Exit',token,os.getpid());require(not has_token(token),'Owned rule survived Stop')
        require(baseline()==before,'Adapter DNS was modified')
        report['checks'].append('Stop removes only the owned rule and preserves adapter DNS configuration')
        # Unknown/modified rules must never be accepted as owned cleanup targets.
        foreign='FlowBridge QA unrelated '+str(uuid.uuid4())
        try:
            ps(command="Add-DnsClientNrptRule -Namespace 'unrelated.test' -NameServers '192.0.2.44' -DisplayName '"+foreign+"'")
            rejected=subprocess.run([str(PS),'-NoProfile','-NonInteractive','-File',str(SCRIPT),'-Action','Enter','-Token',token,'-OwnerProcessId',str(os.getpid()),'-Namespace','only-on-ssh.test'],capture_output=True,timeout=30)
            require(rejected.returncode!=0,'Existing third-party NRPT policy was not rejected')
            policy('Recover',token)
            require(ps(command="[int]@((Get-DnsClientNrptRule) | Where-Object DisplayName -eq '"+foreign+"').Count").strip()=='1','Unrelated NRPT policy was removed')
        finally:
            ps(command="Get-DnsClientNrptRule | Where-Object DisplayName -eq '"+foreign+"' | Remove-DnsClientNrptRule -Force")
        report['checks'].append('Existing policy is refused and unrelated rules survive recovery')
        abi.lib.fb_native_destroy(ident);ident=0
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
        report['passed']=True
    except Exception as error:
        report['error']=str(error);raise
    finally:
        try:policy('Exit',token,os.getpid())
        finally:
            if ident:abi.lib.fb_native_destroy(ident)
            stop(proxy,pt);stop(resolver,rt)
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
