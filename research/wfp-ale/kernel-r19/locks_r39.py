"""R39 native signing provenance: exact checked-in Cargo resolution snapshots.

The two files are taken from ORIGINAL independently audited Windows Actions
#42463556304 (source 2086cbaa). This code reads only filesystem bytes and
does not access BFE, drivers, Windows registry, network or any secret.
"""
import hashlib, json, tomllib
from pathlib import Path

EXPECTED={
    "kernel/Cargo.lock":("a5a740f75007652de912d934499dadc7fe6ebbf14dbeccd0ec4ba748dd3af2c0",5931,27),
    "broker-package/Cargo.lock":("5b0d34550f2a1449447552b74470960e3d9d18f31b5499dc2c1450446f53d2e6",45558,185),
}
def verify_pinned(root:Path)->dict:
    checked={}
    for rel,(sha,size,count) in EXPECTED.items():
        path=root/rel
        raw=path.read_bytes()
        digest=hashlib.sha256(raw).hexdigest()
        if len(raw)!=size or digest!=sha:
            raise RuntimeError("R39 locked dependency drift: "+rel)
        data=tomllib.loads(raw.decode("utf-8"))
        if data.get("version")!=4 or len(data.get("package",[]))!=count:
            raise RuntimeError("R39 locked dependency graph shape mismatch: "+rel)
        if any("checksum" not in p for p in data["package"] if p.get("source","").startswith("registry+")):
            raise RuntimeError("R39 missing registry checksum: "+rel)
        checked[rel]={"bytes":size,"sha256":digest,"packages":count}
    return {"source_run":42463556304,"source_commit":"2086cbaa860671cb3fa13524751fddf3f301e926",
            "lockfiles":checked,"lockfiles_exact_from_original_ci":True,
            "native_driver_loaded":False,"g2_pass":False}
if __name__=="__main__":
    print(json.dumps(verify_pinned(Path(__file__).resolve().parent),sort_keys=True))
