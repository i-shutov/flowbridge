"""Retain exact own source bytes and scoped build evidence, not a native proof."""
import hashlib,json,os,sys,zipfile
from pathlib import Path
root=Path(__file__).resolve().parent
from locks_r39 import verify_pinned
# Fail before producing any CAB/source manifest when a dependency graph drifts.
lock_receipt=verify_pinned(root)
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
files=[]
for parent,patterns in [(root,['*.rs','*.py','*.ps1']), (root/'kernel',['Cargo.toml','Cargo.lock','build.rs','wrapper.h']), (root/'kernel/src',['*.rs']), (root/'broker-package',['Cargo.toml','Cargo.lock']), (root/'trusted-ssh-r37',['Cargo.toml','ssh_r37_smoke.py']), (root/'trusted-ssh-r37/src',['*.rs']), (root/'signing-r38',['*.ps1','*.inf','*.py'])]:
 for pattern in patterns:files.extend(parent.glob(pattern))
files=sorted(set(files))
manifest={}
with zipfile.ZipFile(out/'sources-r24.zip','w',zipfile.ZIP_DEFLATED) as z:
 for path in files:
  raw=path.read_bytes();relative=path.relative_to(root).as_posix()
  z.writestr(relative,raw)
  lf=raw.replace(b'\r\n',b'\n')
  manifest[relative]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'normalized_lf_git_blob_sha1':hashlib.sha1(f'blob {len(lf)}\0'.encode()+lf).hexdigest()}
(out/'source-manifest-r24.json').write_text(json.dumps({'source_sha':os.environ['GITHUB_SHA'],'files':manifest,'source_snapshot_only':True,'locked_dependency_receipt':lock_receipt,'g2_pass':False},indent=2)+'\n')
