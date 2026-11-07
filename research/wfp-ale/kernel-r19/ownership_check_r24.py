"""Compile-time negative checks against the actual Windows adapter, never run it."""
import hashlib,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
CASES={
 'context_not_public':('fn bad(r: broker_windows::Received){let _=r.context;}','E0616'),
 'receipt_not_cloneable':('fn bad(r: broker_windows::Received){let _=r.clone();}','E0599'),
 'accepted_socket_moved':('fn bad(s:std::net::TcpStream){let _=broker_windows::receive(s);let _=s.peer_addr();}','E0382'),
 'borrowed_socket_cannot_detach_receipt':('fn bad(s:&std::net::TcpStream){let _=broker_windows::receive(s);}','E0308'),
 'admitted_upstream_not_public':('fn bad(a:broker_windows::Admitted){let _=a.upstream;}','E0616'),
}
def main():
 if os.name!='nt':raise SystemExit('Windows compiler required; not a native acceptance claim')
 modules='\n'.join('#[allow(dead_code)] #[path='+json.dumps(str(ROOT/p)) +'] mod '+m+';' for p,m in [('kernel/src/handoff.rs','handoff'),('transport.rs','transport'),('broker_windows.rs','broker_windows')])
 control='fn good(s:std::net::TcpStream,d:&broker_windows::Device){let _=broker_windows::receive(s).and_then(|r|r.claim_and_connect(d,1080));}'
 outcomes={}
 with tempfile.TemporaryDirectory(prefix='g2-r24-typecheck-') as td:
  for name,(source,want) in {'control':(control,None),**CASES}.items():
   path=Path(td)/'check.rs';path.write_text(modules+'\n'+source+'\nfn main(){}\n',encoding='utf-8')
   p=subprocess.run(['rustc','--edition=2021','--error-format=json',str(path),'-o',str(Path(td)/'check.exe')],capture_output=True,text=True,timeout=60)
   codes=set()
   for line in p.stderr.splitlines():
    try:
     item=json.loads(line);code=item.get('code')
     if isinstance(code,dict):codes.add(code.get('code'))
    except json.JSONDecodeError:pass
   good=(p.returncode==0) if want is None else (p.returncode!=0 and want in codes)
   outcomes[name]=good
   if not good:raise RuntimeError('adapter_compile_contract_failed_'+name)
 print(json.dumps({'ok':True,'actual_source_compile_checks':outcomes,'windows_adapter_sha256':hashlib.sha256((ROOT/'broker_windows.rs').read_bytes()).hexdigest(),'compiled_programs_executed':False,'kernel_redirect_executed':False,'g2_pass':False},sort_keys=True))
if __name__=='__main__':main()
