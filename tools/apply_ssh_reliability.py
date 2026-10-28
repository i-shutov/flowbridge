from pathlib import Path
p=Path('crates/flowbridge-runtime/src/lib.rs')
s=p.read_text(encoding='utf-8')
start=s.index('    let established = tokio::time::timeout_at(deadline, async {')
end=s.index('    let upstream = match established {',start)
block=s[start:end]
assert block.count('let established = ')==1
expression=block.strip()[len('let established = '):]
assert expression.endswith(';')
expression=expression[:-1]
s=s[:start]+'''    let established = if may_retry {
        '''+expression+'''
    } else {
        // Non-managed routes retain their original per-hop timeout semantics.
        connect_route_guarded(&target, &route,
            Duration::from_millis(config.connect_timeout_ms),
            Duration::from_millis(config.handshake_timeout_ms), config.listen).await
    };
'''+s[end:]
p.write_text(s,encoding='utf-8')
p=Path('crates/flowbridge-runtime/tests/lifecycle.rs')
s=p.read_text(encoding='utf-8')
start=s.index('fn receive_mock_socks(')
head=s[:start]
tail=s[start:]
assert tail.count('proxy.accept().unwrap()')==3
tail=tail.replace('proxy.accept().unwrap()', 'accept_before_deadline(&proxy)')
helper='''fn accept_before_deadline(listener: &TcpListener) -> (TcpStream, std::net::SocketAddr) {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, address)) => {
                stream.set_nonblocking(false).unwrap();
                return (stream, address);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "expected proxy connection before deadline");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("mock proxy accept failed: {error}"),
        }
    }
}

'''
p.write_text(head+helper+tail,encoding='utf-8')
print('Managed-only retry deadline, unchanged other routes, bounded test listeners')
