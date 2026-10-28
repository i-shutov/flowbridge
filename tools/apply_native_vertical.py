from pathlib import Path
p=Path('crates/flowbridge-ffi/src/native_dns.rs')
s=p.read_text();a='use serde::Deserialize;';assert s.count(a)==1
p.write_text(s.replace(a,a+'\nuse std::io;'))
p=Path('crates/flowbridge-ffi/src/native_context.rs')
s=p.read_text();a='let stream = connect_route_guarded(';assert s.count(a)==1
p.write_text(s.replace(a,'let stream = flowbridge_net::connect_route_guarded('))
print('DNS transport dependencies are explicit')
