from pathlib import Path

def edit(path, old, new):
    p=Path(path); s=p.read_text(encoding='utf-8')
    if s.count(old)!=1: raise RuntimeError(f'{path}: match count {s.count(old)}')
    p.write_text(s.replace(old,new),encoding='utf-8')

p='crates/flowbridge-runtime/src/lib.rs'
edit(p,'''    let upstream = match connect_route_guarded(
        &target,
        &route,
        Duration::from_millis(config.connect_timeout_ms),
        Duration::from_millis(config.handshake_timeout_ms),
        config.listen,
    )
    .await
    {''','''    // Retry only a managed, single-hop SOCKS5 establishment, before any
    // application bytes or success reply have been sent. Never replay payload.
    let may_retry = admission.is_some() && route.len() == 1
        && matches!(route[0].kind, flowbridge_core::ProxyKind::Socks5);
    let deadline = Instant::now() + Duration::from_millis(
        config.connect_timeout_ms.saturating_add(config.handshake_timeout_ms));
    let established = tokio::time::timeout_at(deadline, async {
        for attempt in 0..2 {
            if route.first().is_some_and(|p| upstream_gate.borrow().pauses(&p.endpoint)) {
                return Err(NetError::InvalidConfig("managed upstream is paused"));
            }
            let result = connect_route_guarded(&target, &route,
                Duration::from_millis(config.connect_timeout_ms),
                Duration::from_millis(config.handshake_timeout_ms), config.listen).await;
            let retryable = matches!(&result, Err(NetError::Io { stage, source })
                if matches!(*stage, "SOCKS5 greeting" | "SOCKS5 CONNECT response")
                    && matches!(source.kind(), io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted));
            if !may_retry || !retryable || attempt == 1 { return result; }
            lock(&guard.state).event("warn", format!(
                "connection {}: retrying initial managed SOCKS establishment (2/2); no application bytes sent", guard.id));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        unreachable!("bounded establishment loop always returns")
    }).await.unwrap_or(Err(NetError::Timeout { stage: "initial managed connection" }));
    let upstream = match established {''')
p='crates/flowbridge-runtime/tests/lifecycle.rs'
s=Path(p).read_text(encoding='utf-8')
s+=r'''

fn receive_mock_socks(stream: &mut TcpStream) {
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).unwrap();
    let mut request = [0; 10];
    stream.read_exact(&mut request).unwrap();
    assert_eq!(&request[..4], &[5, 1, 0, 1]);
}

#[test]
fn managed_establishment_retry_preserves_coalesced_payload_exactly_once() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = proxied_profile(proxy.local_addr().unwrap());
    let engine = Engine::new(config.clone()).unwrap();
    engine.set_upstream_gate(Some(config.proxies[0].endpoint.clone()), true, 2000).unwrap();
    engine.start().unwrap();
    let server = thread::spawn(move || {
        let (mut first, _) = proxy.accept().unwrap();
        receive_mock_socks(&mut first);
        first.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut buffer = [0; 16];
        let error = first.read(&mut buffer).unwrap_err();
        assert!(matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));
        drop(first);
        let (mut second, _) = proxy.accept().unwrap();
        receive_mock_socks(&mut second);
        second.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut payload = Vec::new();
        second.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, b"once");
        second.write_all(b"accepted once").unwrap();
    });
    let mut client = connect(config.listen);
    client.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2]; client.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 192, 0, 2, 1, 1, 187];
    request.extend_from_slice(b"once");
    client.write_all(&request).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = [0; 10]; client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0);
    let mut result = Vec::new(); client.read_to_end(&mut result).unwrap();
    assert_eq!(result, b"accepted once");
    server.join().unwrap();
    wait(|| engine.snapshot().status.active == 0);
    assert_eq!(engine.snapshot().events.iter().filter(|e| e.message.contains("retrying initial")).count(), 1);
    assert_eq!(engine.snapshot().status.bytes_up, 4);
    engine.stop().unwrap();
}

#[test]
fn managed_establishment_retries_at_most_once_and_never_retries_rejection() {
    for mode in ["eof", "rejected", "auth", "unmanaged"] {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let config = proxied_profile(proxy.local_addr().unwrap());
        let engine = Engine::new(config.clone()).unwrap();
        if mode != "unmanaged" {
            engine.set_upstream_gate(Some(config.proxies[0].endpoint.clone()), true, 1000).unwrap();
        }
        engine.start().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..if mode == "eof" { 2 } else { 1 } {
                let (mut stream, _) = proxy.accept().unwrap();
                if mode == "auth" {
                    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let mut greeting = [0; 3]; stream.read_exact(&mut greeting).unwrap();
                    stream.write_all(&[5, 255]).unwrap();
                } else {
                    receive_mock_socks(&mut stream);
                    if mode == "rejected" {
                        stream.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                    }
                }
            }
            thread::sleep(Duration::from_millis(200));
            proxy.set_nonblocking(true).unwrap();
            assert_eq!(proxy.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        });
        let (_, code) = socks(config.listen, "192.0.2.1:443".parse().unwrap());
        assert_ne!(code, 0);
        server.join().unwrap();
        wait(|| engine.snapshot().status.active == 0);
        assert_eq!(engine.snapshot().status.bytes_up, 0);
        let count = engine.snapshot().events.iter().filter(|e| e.message.contains("retrying initial")).count();
        assert_eq!(count, if mode == "eof" { 1 } else { 0 });
        engine.stop().unwrap();
    }
}
'''
Path(p).write_text(s,encoding='utf-8')
p='tests/ssh_real_integration.py'
edit(p,"            report['passed'] = True",'''            report['connection_establishment_retries'] = sum(
                'retrying initial' in event['message']
                for event in abi.call('fb_engine_snapshot_json', engine)['events'])
            report['passed'] = True''')
p=Path('docs/SSH_RELIABILITY.md')
p.write_text(p.read_text()+'''\nAn intermittent early EOF in a live OpenSSH SOCKS establishment is now handled by at most one additional connection attempt for a managed single-hop SOCKS5 route. Recovery applies only to EOF/reset before any application byte or successful ingress reply, preserves the same admission permits and original combined connect/handshake deadline, rechecks the pause gate and records an event. No retry on authentication, explicit proxy rejection, malformed protocol, timeout, Direct/unmanaged/chain route, or after payload forwarding. The remote side may have seen an empty TCP open; application data is never replayed. This is a bounded recovery policy, not proof of the underlying OpenSSH EOF cause. Regression tests include already coalesced client payload and exact-once delivery.\n''')
print('Bounded pre-payload establishment recovery and strict regression tests added')
