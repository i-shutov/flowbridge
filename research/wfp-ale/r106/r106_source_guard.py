#!/usr/bin/env python3
"""Run from research branch checkout. Read-only source guard; no WFP or network."""
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[1]/'kernel-r19'
sources={
 'broker.rs':'ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c',
 'policy_windows.rs':'acf60334320d970f58af3349ee75fbaa59826602'
}
for name,expected in sources.items():
    path=root/name
    assert path.is_file(),str(path)
    actual=subprocess.check_output(['git','hash-object','--',str(path)],text=True).strip()
    assert actual==expected,(name,actual,expected)
b=(root/'broker.rs').read_text()
p=(root/'policy_windows.rs').read_text()
checks={
 'arm_before_policy':b.index('device.arm(&selection,ports[0],ports[1])?;')<b.index('Installed::activate_admitted(&plan)'),
 'dynamic_session':'session.flags=FWPM_SESSION_FLAG_DYNAMIC' in p,
 'nonpersistent_filter':'f.flags=0;' in p,
 'explicit_close':'FwpmEngineClose0(h)' in p,
 'session_owned':'pub struct Installed{engine:Engine}' in p,
 'policy_teardown':'if let Some(p)=policy{if p.close().is_err()' in b,
 'teardown_after_workers':b.index('workers.finish()')<b.index('p.close()'),
 'external_admission':'native_admission_verified_by_broker' in b,
 'worker_revocation':'if result.is_err(){revoke(&s,&notify);}' in b,
}
assert all(checks.values()),[k for k,v in checks.items() if not v]
print('R106 SOURCE PASS: 9/9 on exact Git blobs')
