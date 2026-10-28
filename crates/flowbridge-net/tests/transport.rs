use base64::{engine::general_purpose::STANDARD, Engine};
use flowbridge_core::{Endpoint, Proxy, ProxyKind};
use flowbridge_net::{
    accept_socks5, connect_route, connect_route_guarded, relay, reply_socks5, NetError,
};
use std::{future::Future, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

const LIMIT: Duration = Duration::from_secs(2);

fn endpoint(host: &str, port: u16) -> Endpoint {
    Endpoint {
        host: host.into(),
        port,
    }
}

async fn listener() -> (TcpListener, Endpoint) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    (listener, endpoint("127.0.0.1", address.port()))
}

fn proxy(kind: ProxyKind, endpoint: Endpoint) -> Proxy {
    Proxy {
        id: "test-proxy".into(),
        kind,
        endpoint,
        username: None,
        password_env: None,
    }
}

fn server(future: impl Future<Output = ()> + Send + 'static) -> JoinHandle<()> {
    tokio::spawn(async { timeout(LIMIT, future).await.expect("mock server timed out") })
}

async fn connect(target: &Endpoint, route: &[Proxy]) -> Result<TcpStream, NetError> {
    connect_route(target, route, LIMIT, LIMIT).await
}

async fn exact(stream: &mut TcpStream, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await.unwrap();
    bytes
}

async fn zero_terminated(stream: &mut TcpStream) -> Vec<u8> {
    let mut value = Vec::new();
    loop {
        let byte = exact(stream, 1).await[0];
        if byte == 0 {
            return value;
        }
        value.push(byte);
        assert!(value.len() <= 255);
    }
}

async fn socks5_request(stream: &mut TcpStream) -> Endpoint {
    let header = exact(stream, 4).await;
    assert_eq!(&header[..3], &[5, 1, 0]);
    let host = match header[3] {
        1 => {
            let bytes: [u8; 4] = exact(stream, 4).await.try_into().unwrap();
            std::net::Ipv4Addr::from(bytes).to_string()
        }
        4 => {
            let bytes: [u8; 16] = exact(stream, 16).await.try_into().unwrap();
            std::net::Ipv6Addr::from(bytes).to_string()
        }
        3 => {
            let length = exact(stream, 1).await[0];
            String::from_utf8(exact(stream, usize::from(length)).await).unwrap()
        }
        _ => panic!("unexpected address type"),
    };
    let port = u16::from_be_bytes(exact(stream, 2).await.try_into().unwrap());
    endpoint(&host, port)
}

async fn header(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.extend(exact(stream, 1).await);
        assert!(bytes.len() < 16384);
    }
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn socks5_remote_dns_fragmented_response_and_tunnel_bytes() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 3).await, [5, 1, 0]);
        stream.write_all(&[5]).await.unwrap();
        tokio::task::yield_now().await;
        stream.write_all(&[0]).await.unwrap();
        assert_eq!(
            socks5_request(&mut stream).await,
            endpoint("never-resolve.invalid", 443)
        );
        // Domain-form BND.ADDR, fragmented at every byte, with payload coalesced
        // with the final response byte. No parser may consume payload bytes.
        for byte in [5, 0, 0, 3, 3, b'b', b'n', b'd', 0] {
            stream.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        stream.write_all(b"\0hello").await.unwrap();
    });
    let mut stream = connect(
        &endpoint("never-resolve.invalid", 443),
        &[proxy(ProxyKind::Socks5, address)],
    )
    .await
    .unwrap();
    assert_eq!(exact(&mut stream, 5).await, b"hello");
    task.await.unwrap();
}

#[tokio::test]
async fn socks5_ipv6_literal_is_encoded_without_local_resolution() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 3).await, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        assert_eq!(
            socks5_request(&mut stream).await,
            endpoint("2001:db8::123", 8443)
        );
        stream.write_all(&[5, 0, 0, 4]).await.unwrap();
        stream.write_all(&[0; 18]).await.unwrap();
    });
    connect(
        &endpoint("2001:db8::123", 8443),
        &[proxy(ProxyKind::Socks5, address)],
    )
    .await
    .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn socks5_rfc1929_authentication_uses_environment_secret() {
    const ENV: &str = "FLOWBRIDGE_NET_TEST_SOCKS5_SUCCESS";
    std::env::set_var(ENV, "sample-secret");
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 3).await, [5, 1, 2]);
        stream.write_all(&[5, 2]).await.unwrap();
        assert_eq!(exact(&mut stream, 2).await, [1, 5]);
        assert_eq!(exact(&mut stream, 5).await, b"alice");
        assert_eq!(exact(&mut stream, 1).await, [13]);
        assert_eq!(exact(&mut stream, 13).await, b"sample-secret");
        stream.write_all(&[1, 0]).await.unwrap();
        assert_eq!(
            socks5_request(&mut stream).await,
            endpoint("target.invalid", 80)
        );
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let mut hop = proxy(ProxyKind::Socks5, address);
    hop.username = Some("alice".into());
    hop.password_env = Some(ENV.into());
    connect(&endpoint("target.invalid", 80), &[hop])
        .await
        .unwrap();
    task.await.unwrap();
    std::env::remove_var(ENV);
}

#[tokio::test]
async fn socks5_required_auth_rejects_noauth_downgrade() {
    const ENV: &str = "FLOWBRIDGE_NET_TEST_SOCKS5_DOWNGRADE";
    std::env::set_var(ENV, "sample-secret");
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 3).await, [5, 1, 2]);
        stream.write_all(&[5, 0]).await.unwrap();
        assert_eq!(
            stream.read(&mut [0]).await.unwrap(),
            0,
            "must stop before sending CONNECT"
        );
    });
    let mut hop = proxy(ProxyKind::Socks5, address);
    hop.username = Some("alice".into());
    hop.password_env = Some(ENV.into());
    let error = connect(&endpoint("target.invalid", 80), &[hop])
        .await
        .unwrap_err();
    assert!(matches!(error, NetError::Authentication { .. }));
    assert!(!format!("{error:?} {error}").contains("sample-secret"));
    task.await.unwrap();
    std::env::remove_var(ENV);
}

#[tokio::test]
async fn socks5_rejected_credentials_stop_before_connect() {
    const ENV: &str = "FLOWBRIDGE_NET_TEST_SOCKS5_REJECT";
    std::env::set_var(ENV, "sample-secret");
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        exact(&mut stream, 3).await;
        stream.write_all(&[5, 2]).await.unwrap();
        exact(&mut stream, 2 + 5 + 1 + 13).await;
        stream.write_all(&[1, 1]).await.unwrap();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    });
    let mut hop = proxy(ProxyKind::Socks5, address);
    hop.username = Some("alice".into());
    hop.password_env = Some(ENV.into());
    let error = connect(&endpoint("target.invalid", 80), &[hop])
        .await
        .unwrap_err();
    assert!(matches!(error, NetError::Authentication { .. }));
    task.await.unwrap();
    std::env::remove_var(ENV);
}

#[tokio::test]
async fn socks4a_remote_hostname_and_user_id() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 8).await, [4, 1, 1, 187, 0, 0, 0, 1]);
        assert_eq!(zero_terminated(&mut stream).await, b"alice");
        assert_eq!(zero_terminated(&mut stream).await, b"target.invalid");
        stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await.unwrap();
        stream.write_all(b"ready").await.unwrap();
    });
    let mut hop = proxy(ProxyKind::Socks4a, address);
    hop.username = Some("alice".into());
    let mut stream = connect(&endpoint("target.invalid", 443), &[hop])
        .await
        .unwrap();
    assert_eq!(exact(&mut stream, 5).await, b"ready");
    task.await.unwrap();
}

#[tokio::test]
async fn socks4a_reserved_marker_ipv4_is_sent_as_hostname() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 8).await, [4, 1, 0, 80, 0, 0, 0, 1]);
        assert!(zero_terminated(&mut stream).await.is_empty());
        assert_eq!(zero_terminated(&mut stream).await, b"0.0.0.7");
        stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await.unwrap();
    });
    connect(
        &endpoint("0.0.0.7", 80),
        &[proxy(ProxyKind::Socks4a, address)],
    )
    .await
    .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn socks4a_rejects_ipv6_and_rejected_requests() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    });
    let error = connect(&endpoint("::1", 80), &[proxy(ProxyKind::Socks4a, address)])
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        NetError::Protocol {
            protocol: "SOCKS4a",
            ..
        }
    ));
    task.await.unwrap();

    let (listener, address) = self::listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        exact(&mut stream, 8).await;
        zero_terminated(&mut stream).await;
        zero_terminated(&mut stream).await;
        stream.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await.unwrap();
    });
    let error = connect(
        &endpoint("target.invalid", 80),
        &[proxy(ProxyKind::Socks4a, address)],
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        NetError::ProxyRejected {
            protocol: "SOCKS4a",
            code: 91
        }
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn http_basic_auth_ipv6_authority_and_coalesced_tunnel_bytes() {
    const ENV: &str = "FLOWBRIDGE_NET_TEST_HTTP_SUCCESS";
    std::env::set_var(ENV, "sample-secret");
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = header(&mut stream).await;
        assert!(request.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: [2001:db8::1]:443\r\n"));
        let token = STANDARD.encode("alice:sample-secret");
        assert!(request.contains(&format!("\r\nProxy-Authorization: Basic {token}\r\n")));
        stream
            .write_all(b"HTTP/1.1 200 Connected\r\nContent-Length: 999\r\n\r\nhello")
            .await
            .unwrap();
    });
    let mut hop = proxy(ProxyKind::HttpConnect, address);
    hop.username = Some("alice".into());
    hop.password_env = Some(ENV.into());
    let mut stream = connect(&endpoint("[2001:db8::1]", 443), &[hop])
        .await
        .unwrap();
    assert_eq!(exact(&mut stream, 5).await, b"hello");
    task.await.unwrap();
    std::env::remove_var(ENV);
}

#[tokio::test]
async fn http_informational_response_then_fragmented_success() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = header(&mut stream).await;
        assert!(request.starts_with("CONNECT target.invalid:80 HTTP/1.1\r\n"));
        assert!(!request.contains("Proxy-Authorization"));
        for byte in b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 200 OK\r\n\r\n" {
            stream.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    connect(
        &endpoint("target.invalid", 80),
        &[proxy(ProxyKind::HttpConnect, address)],
    )
    .await
    .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn http_errors_redact_untrusted_server_text() {
    for code in [407, 403, 502] {
        let (listener, address) = listener().await;
        let task = server(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            header(&mut stream).await;
            stream.write_all(format!("HTTP/1.1 {code} private-server-text\r\nX-Secret: sensitive-header\r\n\r\nsensitive-body").as_bytes()).await.unwrap();
        });
        let error = connect(
            &endpoint("target.invalid", 80),
            &[proxy(ProxyKind::HttpConnect, address)],
        )
        .await
        .unwrap_err();
        if code == 407 {
            assert!(matches!(error, NetError::Authentication { .. }));
        } else {
            assert!(
                matches!(error, NetError::ProxyRejected { code: actual, .. } if actual == code)
            );
        }
        let display = format!("{error:?} {error}");
        for secret in ["private-server-text", "sensitive-header", "sensitive-body"] {
            assert!(!display.contains(secret));
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn http_strict_syntax_and_size_limits() {
    let mut cases: Vec<Vec<u8>> = vec![
        b"HTTP/1.1 200 OK\n\n".to_vec(),
        b"HTTP/1.1 20x bad\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\n invalid: folded\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nInvalid Field: value\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nField: \x01\r\n\r\n".to_vec(),
        b"HTTP/2 200 OK\r\n\r\n".to_vec(),
    ];
    cases.push(
        [
            b"HTTP/1.1 200 OK\r\nX: ".as_slice(),
            &vec![b'a'; 4096],
            b"\r\n\r\n",
        ]
        .concat(),
    );
    cases.push(
        [
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            &b"X: y\r\n".repeat(3000),
            b"\r\n",
        ]
        .concat(),
    );
    for response in cases {
        let (listener, address) = listener().await;
        let task = server(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            header(&mut stream).await;
            let _ = stream.write_all(&response).await;
        });
        let error = connect(
            &endpoint("target.invalid", 80),
            &[proxy(ProxyKind::HttpConnect, address)],
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            NetError::Protocol {
                protocol: "HTTP CONNECT",
                ..
            }
        ));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn mixed_chain_negotiates_in_order_on_one_stream() {
    let (listener, address) = listener().await;
    let task = server(async move {
        // Exactly one socket serves all three handshakes. Subsequent proxy
        // endpoint names intentionally cannot be resolved by the client.
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 3).await, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        assert_eq!(
            socks5_request(&mut stream).await,
            endpoint("second-hop.invalid", 8080)
        );
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        assert!(header(&mut stream)
            .await
            .starts_with("CONNECT third-hop.invalid:1080 HTTP/1.1\r\n"));
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        assert_eq!(exact(&mut stream, 8).await, [4, 1, 1, 187, 0, 0, 0, 1]);
        assert!(zero_terminated(&mut stream).await.is_empty());
        assert_eq!(zero_terminated(&mut stream).await, b"final-target.invalid");
        stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await.unwrap();
        stream.write_all(b"tunneled").await.unwrap();
    });
    let route = [
        proxy(ProxyKind::Socks5, address),
        proxy(ProxyKind::HttpConnect, endpoint("second-hop.invalid", 8080)),
        proxy(ProxyKind::Socks4a, endpoint("third-hop.invalid", 1080)),
    ];
    let mut stream = connect(&endpoint("final-target.invalid", 443), &route)
        .await
        .unwrap();
    assert_eq!(exact(&mut stream, 8).await, b"tunneled");
    task.await.unwrap();
}

#[tokio::test]
async fn missing_secret_and_injection_are_rejected_before_opening_socket() {
    const ENV: &str = "FLOWBRIDGE_NET_TEST_MISSING_SECRET";
    std::env::remove_var(ENV);
    let (listener, address) = listener().await;
    let mut hop = proxy(ProxyKind::HttpConnect, address.clone());
    hop.username = Some("alice".into());
    hop.password_env = Some(ENV.into());
    let error = connect(&endpoint("target.invalid", 80), &[hop])
        .await
        .unwrap_err();
    assert!(matches!(error, NetError::Authentication { .. }));
    for bad_host in [
        "good.invalid\r\nInjected: header",
        "127.1",
        "2130706433",
        "0x7f000001",
        "127.0.0.01",
    ] {
        let error = connect(
            &endpoint(bad_host, 80),
            &[proxy(ProxyKind::HttpConnect, address.clone())],
        )
        .await
        .unwrap_err();
        assert!(matches!(error, NetError::InvalidEndpoint(_)));
    }
    assert!(timeout(Duration::from_millis(30), listener.accept())
        .await
        .is_err());
}

#[tokio::test]
async fn proxy_rejection_never_falls_back_to_direct() {
    let (destination_listener, destination) = listener().await;
    let (proxy_listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = proxy_listener.accept().await.unwrap();
        exact(&mut stream, 3).await;
        stream.write_all(&[5, 0]).await.unwrap();
        socks5_request(&mut stream).await;
        stream
            .write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let error = connect(&destination, &[proxy(ProxyKind::Socks5, address)])
        .await
        .unwrap_err();
    assert!(matches!(error, NetError::ProxyRejected { code: 2, .. }));
    assert!(
        timeout(Duration::from_millis(30), destination_listener.accept())
            .await
            .is_err()
    );
    task.await.unwrap();
}

#[tokio::test]
async fn proxy_handshake_has_a_deadline() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 3).await, [5, 1, 0]);
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    });
    let error = connect_route(
        &endpoint("target.invalid", 80),
        &[proxy(ProxyKind::Socks5, address)],
        LIMIT,
        Duration::from_millis(30),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        NetError::Timeout {
            stage: "proxy handshake"
        }
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn explicit_empty_route_connects_directly() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"direct").await.unwrap();
    });
    let mut stream = connect(&address, &[]).await.unwrap();
    assert_eq!(exact(&mut stream, 6).await, b"direct");
    task.await.unwrap();
}

#[tokio::test]
async fn socks5_ingress_fragmented_handshake_preserves_coalesced_payload() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let target = accept_socks5(&mut stream, LIMIT).await.unwrap();
        assert_eq!(target, endpoint("target.invalid", 443));
        reply_socks5(&mut stream, 0).await.unwrap();
        assert_eq!(exact(&mut stream, 7).await, b"payload");
    });
    let mut stream = TcpStream::connect((address.host.as_str(), address.port))
        .await
        .unwrap();
    for byte in [5, 2, 2, 0] {
        stream.write_all(&[byte]).await.unwrap();
        tokio::task::yield_now().await;
    }
    assert_eq!(exact(&mut stream, 2).await, [5, 0]);
    let mut packet = vec![5, 1, 0, 3, 14];
    packet.extend_from_slice(b"target.invalid");
    packet.extend_from_slice(&[1, 187]);
    packet.extend_from_slice(b"payload");
    stream.write_all(&packet).await.unwrap();
    assert_eq!(exact(&mut stream, 10).await, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    task.await.unwrap();
}

#[tokio::test]
async fn socks5_ingress_rejects_unsupported_commands_and_bad_addresses() {
    let cases = vec![
        (vec![5, 2, 0, 1], 7),
        (vec![5, 3, 0, 1], 7),
        (vec![5, 255, 0, 1], 7),
        (vec![4, 1, 0, 1], 1),
        (vec![5, 1, 1, 1], 1),
        (vec![5, 1, 0, 9], 8),
        (vec![5, 1, 0, 3, 0], 8),
        (vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 0], 8),
        (vec![5, 1, 0, 3, 3, b'a', b'\r', b'b', 0, 80], 8),
    ];
    for (request, code) in cases {
        let (listener, address) = listener().await;
        let task = server(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(accept_socks5(&mut stream, LIMIT).await.is_err());
        });
        let mut stream = TcpStream::connect((address.host.as_str(), address.port))
            .await
            .unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        assert_eq!(exact(&mut stream, 2).await, [5, 0]);
        stream.write_all(&request).await.unwrap();
        assert_eq!(
            exact(&mut stream, 10).await,
            [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn socks5_ingress_requires_noauth_and_times_out_stalled_clients() {
    let (listener, address) = listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            accept_socks5(&mut stream, LIMIT).await.unwrap_err(),
            NetError::Authentication { .. }
        ));
    });
    let mut stream = TcpStream::connect((address.host.as_str(), address.port))
        .await
        .unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(exact(&mut stream, 2).await, [5, 255]);
    task.await.unwrap();

    let (listener, address) = self::listener().await;
    let task = server(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            accept_socks5(&mut stream, Duration::from_millis(30))
                .await
                .unwrap_err(),
            NetError::Timeout { .. }
        ));
    });
    let _stream = TcpStream::connect((address.host.as_str(), address.port))
        .await
        .unwrap();
    task.await.unwrap();
}

async fn socket_pair() -> (TcpStream, TcpStream) {
    let (listener, address) = listener().await;
    let client = TcpStream::connect((address.host.as_str(), address.port))
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[tokio::test]
async fn relay_half_close_delivers_response_after_request_eof() {
    let (mut client, mut ingress) = socket_pair().await;
    let (mut upstream, mut destination) = socket_pair().await;
    let relay_task = tokio::spawn(async move { relay(&mut ingress, &mut upstream, LIMIT).await });
    let task = server(async move {
        let mut request = Vec::new();
        destination.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        destination.write_all(b"response").await.unwrap();
        destination.shutdown().await.unwrap();
    });
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"response");
    assert_eq!(relay_task.await.unwrap().unwrap(), (7, 8));
    task.await.unwrap();
}

#[tokio::test]
async fn relay_activity_in_one_direction_resets_shared_idle_deadline() {
    let (mut client, mut ingress) = socket_pair().await;
    let (mut upstream, mut destination) = socket_pair().await;
    let relay_task = tokio::spawn(async move {
        relay(&mut ingress, &mut upstream, Duration::from_millis(150)).await
    });
    let task = server(async move {
        // Traffic lasts over twice the timeout; the request direction is EOF.
        let mut input = Vec::new();
        destination.read_to_end(&mut input).await.unwrap();
        assert!(input.is_empty());
        for _ in 0..8 {
            sleep(Duration::from_millis(40)).await;
            destination.write_all(b"x").await.unwrap();
        }
        destination.shutdown().await.unwrap();
    });
    client.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    timeout(LIMIT, client.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"xxxxxxxx");
    assert_eq!(relay_task.await.unwrap().unwrap(), (0, 8));
    task.await.unwrap();
}

#[tokio::test]
async fn relay_idle_timeout_is_not_a_total_transfer_timeout() {
    let (_client, mut ingress) = socket_pair().await;
    let (mut upstream, _destination) = socket_pair().await;
    let error = timeout(
        LIMIT,
        relay(&mut ingress, &mut upstream, Duration::from_millis(30)),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(error, NetError::IdleTimeout));
}

#[tokio::test]
async fn invalid_timeouts_and_oversized_chains_are_rejected() {
    let target = endpoint("target.invalid", 80);
    assert!(matches!(
        connect_route(&target, &[], Duration::ZERO, LIMIT)
            .await
            .unwrap_err(),
        NetError::InvalidConfig(_)
    ));
    let route = vec![proxy(ProxyKind::Socks5, endpoint("127.0.0.1", 9)); 17];
    assert!(matches!(
        connect(&target, &route).await.unwrap_err(),
        NetError::InvalidConfig(_)
    ));
}

#[tokio::test]
async fn guarded_route_rejects_resolved_localhost_before_any_connection() {
    let (listener, address) = listener().await;
    let forbidden = listener.local_addr().unwrap();
    // The guard must operate on the resolver result, not just compare endpoint
    // strings to the listener's literal IP address.
    for route in [
        Vec::new(),
        vec![proxy(
            ProxyKind::Socks5,
            endpoint("localhost", address.port),
        )],
    ] {
        let target = if route.is_empty() {
            endpoint("localhost", address.port)
        } else {
            endpoint("remote-target.invalid", 443)
        };
        let error = connect_route_guarded(&target, &route, LIMIT, LIMIT, forbidden)
            .await
            .unwrap_err();
        assert!(matches!(error, NetError::RecursiveListener));
    }
    assert!(timeout(Duration::from_millis(30), listener.accept())
        .await
        .is_err());
}

#[tokio::test]
async fn guarded_route_preserves_remote_resolution_for_later_hops_and_targets() {
    let (forbidden_listener, forbidden_endpoint) = listener().await;
    let forbidden = forbidden_listener.local_addr().unwrap();
    let (proxy_listener, address) = listener().await;
    let remote_port = forbidden_endpoint.port;
    let task = server(async move {
        let (mut stream, _) = proxy_listener.accept().await.unwrap();
        assert_eq!(exact(&mut stream, 3).await, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        assert_eq!(
            socks5_request(&mut stream).await,
            endpoint("localhost", remote_port)
        );
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let request = header(&mut stream).await;
        assert!(request.starts_with(&format!("CONNECT localhost:{remote_port} HTTP/1.1\r\n")));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nremote")
            .await
            .unwrap();
    });
    let route = [
        proxy(ProxyKind::Socks5, address),
        proxy(ProxyKind::HttpConnect, endpoint("localhost", remote_port)),
    ];
    let mut stream = connect_route_guarded(
        &endpoint("localhost", remote_port),
        &route,
        LIMIT,
        LIMIT,
        forbidden,
    )
    .await
    .unwrap();
    assert_eq!(exact(&mut stream, 6).await, b"remote");
    assert!(
        timeout(Duration::from_millis(30), forbidden_listener.accept())
            .await
            .is_err()
    );
    task.await.unwrap();
}

#[tokio::test]
async fn native_preparation_binds_the_actual_socket_before_connect() {
    use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let calls = AtomicUsize::new(0);
    let prepared_port = AtomicU16::new(0);
    let prepare = |socket: &tokio::net::TcpSocket| {
        // A SYN before preparation would already be queued in the server's
        // accept backlog. Binding also fails if this socket is connected.
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
        socket.bind("127.0.0.1:0".parse().unwrap())?;
        prepared_port.store(socket.local_addr()?.port(), Ordering::SeqCst);
        socket.set_nodelay(true)?;
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };
    let stream = flowbridge_net::connect_route_prepared(
        &endpoint("127.0.0.1", address.port()),
        &[],
        LIMIT,
        LIMIT,
        "127.0.0.1:1".parse().unwrap(),
        &prepare,
    )
    .await
    .unwrap();
    let (_, peer) = listener.accept().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(peer.port(), prepared_port.load(Ordering::SeqCst));
    assert_eq!(stream.local_addr().unwrap().port(), peer.port());
    assert!(stream.nodelay().unwrap());
}

#[tokio::test]
async fn native_preparation_failure_never_connects_proxy_or_direct_target() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let destination = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    upstream.set_nonblocking(true).unwrap();
    let target = endpoint("127.0.0.1", destination.local_addr().unwrap().port());
    let hop = proxy(
        ProxyKind::Socks5,
        endpoint("127.0.0.1", upstream.local_addr().unwrap().port()),
    );
    let calls = AtomicUsize::new(0);
    let prepare = |socket: &tokio::net::TcpSocket| {
        socket.bind("127.0.0.1:0".parse().unwrap())?;
        calls.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "preparation rejected",
        ))
    };
    for route in [Vec::new(), vec![hop]] {
        let error = flowbridge_net::connect_route_prepared(
            &target,
            &route,
            LIMIT,
            LIMIT,
            "127.0.0.1:1".parse().unwrap(),
            &prepare,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, NetError::Io { stage: "native pre-connect preparation", source } if source.kind() == std::io::ErrorKind::PermissionDenied)
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    for listener in [destination, upstream] {
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[tokio::test]
async fn native_preparation_is_not_called_for_recursive_or_invalid_routes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let calls = AtomicUsize::new(0);
    let prepare = |_: &tokio::net::TcpSocket| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };
    let error = flowbridge_net::connect_route_prepared(
        &endpoint("localhost", address.port()),
        &[],
        LIMIT,
        LIMIT,
        address,
        &prepare,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, NetError::RecursiveListener));
    let error = flowbridge_net::connect_route_prepared(
        &endpoint("invalid\r\nhost", address.port()),
        &[],
        LIMIT,
        LIMIT,
        address,
        &prepare,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, NetError::InvalidEndpoint(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}
