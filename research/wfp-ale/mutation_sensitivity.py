import pathlib, subprocess, tempfile, shutil, json
root=pathlib.Path(__file__).parent
source=(root/'endpoint_witness_model.py').read_text()
audit=root/'auth_lifetime_audit.py'
mutants={
 'no_endpoint_retirement':('        self.poisoned_endpoints.add(endpoint)','        pass  # unsafe: no endpoint retirement'),
 'ignore_duplicate_auth':('        if event.endpoint in self.auth:\n            self._retire_endpoint(event.endpoint)\n            return \'AMBIGUOUS_ENDPOINT\'','        if False:  # unsafe: duplicate AUTH\n            self._retire_endpoint(event.endpoint)\n            return \'AMBIGUOUS_ENDPOINT\''),
 'reauthorize_promoted':('        if event.reauthorize:\n            return \'REAUTHORIZE_NOT_NEW_PROOF\'','        if False:  # unsafe: promotes reauthorization\n            return \'REAUTHORIZE_NOT_NEW_PROOF\''),
 'allow_endpoint_overlap':('        if request.endpoint in self.auth or any(p.endpoint == request.endpoint for p in self.redirects.values()):','        if False:  # unsafe: two pending tickets'),
 'skip_image_identity':('                or event.path_identity != owner.exe_identity','                or False  # unsafe: no image check'),
}
results={}
for name,(old,new) in mutants.items():
 assert source.count(old)==1,(name,source.count(old))
 with tempfile.TemporaryDirectory() as d:
  path=pathlib.Path(d)
  (path/'endpoint_witness_model.py').write_text(source.replace(old,new))
  shutil.copyfile(audit,path/'auth_lifetime_audit.py')
  run=subprocess.run(['python3',str(path/'auth_lifetime_audit.py')],capture_output=True,text=True,timeout=10)
  results[name]='DETECTED' if run.returncode!=0 else 'MISSED'
print(json.dumps(results,sort_keys=True))
assert all(x=='DETECTED' for x in results.values())
