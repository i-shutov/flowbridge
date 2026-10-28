"""Third exact-match preparation pass; no user data or credentials."""
from pathlib import Path
p = Path('crates/flowbridge-ffi/src/lib.rs')
s = p.read_text(encoding='utf-8')
old = 'json!({"ok":true,"status":snapshot.status,"connections":snapshot.connections,"events":snapshot.events}),'
new = 'json!({"ok":true,"status":snapshot.status,"connections":snapshot.connections,"events":snapshot.events,"managed_upstream":snapshot.managed_upstream}),'
assert s.count(old) == 1, 'Snapshot serialization changed; refuse a speculative patch'
p.write_text(s.replace(old, new), encoding='utf-8')
print('Managed upstream counters are now included in the FFI snapshot.')
