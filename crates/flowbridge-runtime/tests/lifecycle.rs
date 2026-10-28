use flowbridge_core::{Action, Config, Endpoint, Proxy, ProxyKind, Rule};
use flowbridge_runtime::Engine;
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn profile() -> Config {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut config = Config::from_json(include_str!("../../../examples/direct.json")).unwrap();
    config.listen = address;
    config.handshake_timeout_ms = 300_000;
    config
}
fn connect(address: SocketAddr) -> TcpStream {
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}
fn socks(address: SocketAddr, target: SocketAddr) -> (TcpStream, u8) {
    let mut socket = connect(address);
    socket.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0; 2];
    socket.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0]);
    let ip = match target.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => panic!("IPv4 test"),
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&target.port().to_be_bytes());
    socket.write_all(&request).unwrap();
    let mut reply = [0; 10];
    socket.read_exact(&mut reply).unwrap();
    (socket, reply[1])
}
fn wait(mut check: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(3);
    while !check() {
        assert!(Instant::now() < until, "condition did not become true");
        thread::sleep(Duration::from_millis(2));
    }
}

fn proxied_profile(upstream: SocketAddr) -> Config {
    let mut config = profile();
    config.proxies.push(Proxy {
        id: "managed".into(),
        kind: ProxyKind::Socks5,
        endpoint: Endpoint {
            host: upstream.ip().to_string(),
            port: upstream.port(),
        },
        username: None,
        password_env: None,
    });
    config.default_action = Action::Proxy {
        id: "managed".into(),
    };
    config
}

#[test]
fn managed_reconnect_waits_before_open_and_resumes_new_flow_without_replay() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let config = proxied_profile(proxy.local_addr().unwrap());
    let endpoint = config.proxies[0].endpoint.clone();
    let engine = Engine::new(config.clone()).unwrap();
    engine
        .set_upstream_gate(Some(endpoint.clone()), false, 2000)
        .unwrap();
    engine.start().unwrap();
    let client = thread::spawn(move || {
        let (mut client, code) = socks(config.listen, "192.0.2.1:443".parse().unwrap());
        assert_eq!(code, 0);
        client.write_all(b"once").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"received once");
    });
    wait(|| {
        engine
            .snapshot()
            .connections
            .iter()
            .any(|c| c.state == "waiting_for_tunnel")
    });
    assert_eq!(
        proxy.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    proxy.set_nonblocking(false).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = proxy.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).unwrap();
        let mut request = [0; 10];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 1]);
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"once");
        stream.write_all(b"received once").unwrap();
    });
    engine
        .set_upstream_gate(Some(endpoint), true, 2000)
        .unwrap();
    client.join().unwrap();
    server.join().unwrap();
    engine.stop().unwrap();
}

#[test]
fn managed_reconnect_timeout_and_stop_are_bounded_and_direct_is_not_paused() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let config = proxied_profile(proxy.local_addr().unwrap());
    let endpoint = config.proxies[0].endpoint.clone();
    let engine = Engine::new(config.clone()).unwrap();
    assert!(engine
        .set_upstream_gate(
            Some(Endpoint {
                host: "example.com".into(),
                port: 1080
            }),
            false,
            100
        )
        .is_err());
    assert!(engine
        .set_upstream_gate(Some(endpoint.clone()), false, 120001)
        .is_err());
    engine
        .set_upstream_gate(Some(endpoint.clone()), false, 100)
        .unwrap();
    engine.start().unwrap();
    let start = Instant::now();
    let (_, code) = socks(config.listen, "192.0.2.1:443".parse().unwrap());
    assert_ne!(code, 0);
    assert!(start.elapsed() < Duration::from_secs(1));
    wait(|| engine.snapshot().status.active == 0);
    assert_eq!(
        proxy.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    engine
        .set_upstream_gate(Some(endpoint), false, 120000)
        .unwrap();
    let pending = thread::spawn(move || {
        let mut c = connect(config.listen);
        c.write_all(&[5, 1, 0]).unwrap();
        let mut hello = [0; 2];
        c.read_exact(&mut hello).unwrap();
        c.write_all(&[5, 1, 0, 1, 192, 0, 2, 1, 1, 187]).unwrap();
        let mut b = [0];
        c.read(&mut b)
    });
    wait(|| {
        engine
            .snapshot()
            .connections
            .iter()
            .any(|c| c.state == "waiting_for_tunnel")
    });
    let start = Instant::now();
    engine.stop().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    let stopped = pending.join().unwrap();
    assert!(matches!(stopped, Ok(0)) || stopped.is_err());
    let direct = profile();
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let engine = Engine::new(direct.clone()).unwrap();
    engine
        .set_upstream_gate(
            Some(Endpoint {
                host: "127.0.0.1".into(),
                port: proxy.local_addr().unwrap().port(),
            }),
            false,
            120000,
        )
        .unwrap();
    engine.start().unwrap();
    let (_, code) = socks(direct.listen, target.local_addr().unwrap());
    assert_eq!(code, 0);
    engine.stop().unwrap();
}
#[test]
fn occupied_port_start_acknowledgement_restart_and_bounded_cancel() {
    let config = profile();
    let occupied = TcpListener::bind(config.listen).unwrap();
    let engine = Engine::new(config.clone()).unwrap();
    assert!(engine.start().is_err());
    assert!(!engine.snapshot().status.running);
    drop(occupied);
    assert!(engine.start().unwrap().running);
    assert!(TcpListener::bind(config.listen).is_err());
    let _pending = connect(config.listen);
    wait(|| engine.snapshot().status.active == 1);
    let start = Instant::now();
    assert!(!engine.stop().unwrap().running);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(engine.snapshot().status.active, 0);
    let port = TcpListener::bind(config.listen).unwrap();
    drop(port);
    assert!(engine.start().unwrap().running);
    engine.stop().unwrap();
}
#[test]
fn reload_validates_before_atomic_apply_and_preserves_running_settings() {
    let config = profile();
    let engine = Engine::new(config.clone()).unwrap();
    engine.start().unwrap();
    assert!(engine.reload_json("{}").is_err());
    assert_eq!(engine.snapshot().status.generation, 1);
    let mut changed = config.clone();
    changed.max_connections += 1;
    assert!(engine.reload(changed.clone()).is_err());
    assert_eq!(engine.snapshot().status.generation, 1);
    let mut invalid = config.clone();
    invalid.connect_timeout_ms = 0;
    assert!(engine.reload(invalid).is_err());
    assert_eq!(engine.snapshot().status.generation, 1);
    let mut policy = config;
    policy.default_action = Action::Block;
    assert_eq!(engine.reload(policy).unwrap().generation, 2);
    engine.stop().unwrap();
    assert_eq!(engine.reload(changed).unwrap().generation, 3);
}
#[test]
fn traffic_metrics_half_close_and_existing_revision_survive_reload() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"beforeafter");
        stream.write_all(b"response after EOF").unwrap();
    });
    let config = profile();
    let engine = Engine::new(config.clone()).unwrap();
    engine.start().unwrap();
    let (mut client, code) = socks(config.listen, target);
    assert_eq!(code, 0);
    client.write_all(b"before").unwrap();
    wait(|| engine.snapshot().status.bytes_up == 6);
    let live = engine.snapshot();
    assert_eq!(live.connections[0].state, "active");
    assert_eq!(live.connections[0].generation, 1);
    let mut blocked = config.clone();
    blocked.default_action = Action::Block;
    engine.reload(blocked).unwrap();
    let (_, code) = socks(config.listen, target);
    assert_eq!(code, 2);
    client.write_all(b"after").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"response after EOF");
    responder.join().unwrap();
    wait(|| engine.snapshot().status.active == 0);
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.status.bytes_up, 11);
    assert_eq!(snapshot.status.bytes_down, 18);
    assert_eq!(snapshot.status.completed, 1);
    assert_eq!(snapshot.status.failed, 1);
    assert_eq!(snapshot.connections[1].generation, 2);
    engine.stop().unwrap();
}
#[test]
fn application_rules_rejected_and_capacity_cancels_cleanly() {
    let mut config = profile();
    config.rules.push(Rule {
        id: "process".into(),
        enabled: true,
        applications: vec!["app".into()],
        hosts: vec![],
        networks: vec![],
        ports: vec![],
        action: Action::Direct,
    });
    assert!(Engine::new(config.clone()).is_err());
    config.rules[0].enabled = false;
    config.max_connections = 1;
    let engine = Arc::new(Engine::new(config.clone()).unwrap());
    engine.start().unwrap();
    let first = connect(config.listen);
    wait(|| engine.snapshot().status.active == 1);
    let mut second = connect(config.listen);
    let mut byte = [0];
    let result = second.read(&mut byte);
    assert!(matches!(result, Ok(0) | Err(_)));
    assert_eq!(engine.snapshot().status.accepted, 1);
    let a = engine.clone();
    let b = engine.clone();
    let one = thread::spawn(move || a.stop().unwrap());
    let two = thread::spawn(move || b.stop().unwrap());
    one.join().unwrap();
    two.join().unwrap();
    drop(first);
    assert_eq!(engine.snapshot().status.active, 0);
}
#[test]
fn recent_connection_and_event_histories_are_bounded() {
    let mut config = profile();
    config.default_action = Action::Block;
    let engine = Engine::new(config.clone()).unwrap();
    engine.start().unwrap();
    let target = "127.0.0.1:9".parse().unwrap();
    for _ in 0..530 {
        let (_, code) = socks(config.listen, target);
        assert_eq!(code, 2);
    }
    wait(|| engine.snapshot().status.active == 0);
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.status.accepted, 530);
    assert_eq!(snapshot.status.failed, 530);
    assert_eq!(snapshot.connections.len(), 512);
    assert_eq!(snapshot.events.len(), 256);
    assert!(snapshot.connections[0].id > 1);
    assert!(snapshot.events[0].seq > 1);
    engine.stop().unwrap();
}

#[test]
fn active_record_and_live_metrics_survive_more_than_512_finished_flows() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = server.local_addr().unwrap();
    let responder = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut chunk = [0; 4];
        while stream.read_exact(&mut chunk).is_ok() {
            stream.write_all(&chunk).unwrap();
        }
    });
    let config = profile();
    let engine = Engine::new(config.clone()).unwrap();
    engine.start().unwrap();
    let (mut live, code) = socks(config.listen, target);
    assert_eq!(code, 0);
    live.write_all(b"live").unwrap();
    let mut echo = [0; 4];
    live.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"live");
    let id = engine.snapshot().connections[0].id;
    let mut blocked = config.clone();
    blocked.default_action = Action::Block;
    engine.reload(blocked).unwrap();
    for _ in 0..530 {
        let (_, code) = socks(config.listen, target);
        assert_eq!(code, 2);
    }
    wait(|| engine.snapshot().status.active == 1);
    live.write_all(b"kept").unwrap();
    live.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"kept");
    wait(|| engine.snapshot().status.bytes_down == 8);
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.status.accepted, 531);
    assert_eq!(snapshot.status.failed, 530);
    assert_eq!(snapshot.connections.len(), 513);
    let record = snapshot
        .connections
        .iter()
        .find(|c| c.id == id)
        .expect("active record must remain visible");
    assert_eq!(record.state, "active");
    assert_eq!(record.generation, 1);
    assert_eq!(record.host, target.ip().to_string());
    assert_eq!(record.bytes_up, 8);
    assert_eq!(record.bytes_down, 8);
    engine.stop().unwrap();
    responder.join().unwrap();
    let stopped = engine.snapshot();
    assert_eq!(stopped.connections.len(), 512);
    assert_eq!(stopped.status.active, 0);
    assert!(stopped
        .connections
        .iter()
        .any(|c| c.id == id && c.error.as_deref() == Some("connection cancelled")));
}
