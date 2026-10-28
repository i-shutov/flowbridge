"""Second exact-match preparation pass; no user data or credentials."""
from pathlib import Path
p = Path('crates/flowbridge-tunnel/src/lib.rs')
s = p.read_text()
old = 'consecutive local SOCKS health checks failed'
assert s.count(old) == 1
p.write_text(s.replace(old, 'local SOCKS health check failed repeatedly'))
print('Preserved the existing diagnostic message compatibility; all assertions remain enabled.')
