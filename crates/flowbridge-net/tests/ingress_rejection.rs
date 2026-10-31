//! Regression coverage for Windows TCP resets during a SOCKS refusal.
use flowbridge_net::{accept_socks5, NetError};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

#[tokio::test]
async fn rejection_delivers_reply_and_drains_complete_or_fragmented_request() {
    for command in [2, 3, 255] {
        for fragmented in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let error = accept_socks5(&mut stream, Duration::from_secs(2))
                    .await
                    .unwrap_err();
                assert!(matches!(error, NetError::UnsupportedCommand(c) if c == command));
                // Deterministic regression: the old implementation left the
                // address/port unread, even when Windows happened to send REP.
                let mut pending = [0; 1];
                match stream.try_read(&mut pending) {
                    Ok(0) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    other => panic!("refused request left unread bytes: {other:?}"),
                }
            });
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            let mut request = vec![5, command, 0, 3, 14];
            request.extend_from_slice(b"target.invalid");
            request.extend_from_slice(&[1, 187]);
            if fragmented {
                for chunk in request.chunks(3) {
                    client.write_all(chunk).await.unwrap();
                    tokio::task::yield_now().await;
                }
            } else {
                client.write_all(&request).await.unwrap();
            }
            client.shutdown().await.unwrap();
            let mut reply = [0; 10];
            time::timeout(Duration::from_secs(3), client.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
            assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
            time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

#[tokio::test]
async fn rejected_header_only_peer_cannot_hold_connection_open() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let error = accept_socks5(&mut stream, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(error, NetError::UnsupportedCommand(3)));
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&[5, 1, 0, 5, 3, 0, 1]).await.unwrap();
    let mut response = [0; 12];
    time::timeout(Duration::from_secs(2), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    // Client deliberately sends neither destination bytes nor EOF. Cleanup
    // must have its own bounded grace, rather than waiting the full five seconds.
    time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}
