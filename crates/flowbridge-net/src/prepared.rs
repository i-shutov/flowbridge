//! Per-attempt socket preparation, shared by production and fault-injection tests.

use super::{io_error, NetError};
use std::{future::Future, io, net::SocketAddr};
use tokio::net::{TcpSocket, TcpStream};

pub(super) async fn connect<F, Fut>(
    addresses: &[SocketAddr],
    prepare: &(dyn Fn(&TcpSocket) -> io::Result<()> + Sync),
    dial: F,
) -> Result<TcpStream, NetError>
where
    F: Fn(TcpSocket, SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>>,
{
    let mut last_error = io::Error::new(io::ErrorKind::AddrNotAvailable, "no resolved addresses");
    for address in addresses {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|e| io_error("socket creation", e))?;
        // Never connect, retry without records, or select another route after
        // preparation fails. The caller owns the overall connection deadline.
        prepare(&socket).map_err(|e| io_error("native pre-connect preparation", e))?;
        match dial(socket, *address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = error,
        }
    }
    Err(io_error("TCP connect", last_error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use std::time::Duration;
    use tokio::{net::TcpListener, time};

    // A bound-but-not-listening socket is NOT a portable refused connection:
    // macOS and Windows may wait for TCP retries. Inject the failure instead.
    #[tokio::test]
    async fn every_address_retry_has_a_fresh_prepared_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();
        let prepared_ports = Mutex::new(Vec::new());
        let attempts = AtomicUsize::new(0);
        let prepare = |socket: &TcpSocket| {
            assert!(!socket.nodelay()?);
            socket.bind("127.0.0.1:0".parse().unwrap())?;
            prepared_ports
                .lock()
                .unwrap()
                .push(socket.local_addr()?.port());
            socket.set_nodelay(true)
        };
        let dial = |socket: TcpSocket, address: SocketAddr| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "injected refusal",
                    ))
                } else {
                    socket.connect(address).await
                }
            }
        };
        let stream = time::timeout(
            Duration::from_secs(5),
            connect(&[reachable, reachable], &prepare, dial),
        )
        .await
        .unwrap()
        .unwrap();
        let (_, peer) = time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let ports = prepared_ports.lock().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(ports.len(), 2);
        assert_eq!(peer.port(), ports[1]);
        assert_eq!(stream.local_addr().unwrap().port(), ports[1]);
        assert!(stream.nodelay().unwrap());
    }

    #[tokio::test]
    async fn preparation_failure_on_retry_aborts_before_that_connect_or_later_addresses() {
        let calls = AtomicUsize::new(0);
        let attempts = AtomicUsize::new(0);
        let prepare = |_: &TcpSocket| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "records rejected",
                ))
            }
        };
        let dial = |_: TcpSocket, _: SocketAddr| {
            attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "injected refusal",
            )))
        };
        let addresses = ["127.0.0.1:1".parse().unwrap(); 3];
        let error = connect(&addresses, &prepare, dial).await.unwrap_err();
        assert!(matches!(
            error,
            NetError::Io {
                stage: "native pre-connect preparation",
                source
            }
                if source.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn empty_addresses_do_not_prepare_or_dial() {
        let prepare = |_: &TcpSocket| -> io::Result<()> { panic!("unexpected preparation") };
        let dial = |_: TcpSocket, _: SocketAddr| {
            std::future::ready(Err(io::Error::other("unexpected dial")))
        };
        let error = connect(&[], &prepare, dial).await.unwrap_err();
        assert!(matches!(
            error,
            NetError::Io {
                stage: "TCP connect",
                source
            }
                if source.kind() == io::ErrorKind::AddrNotAvailable
        ));
    }

    #[tokio::test]
    async fn first_preparation_failure_never_dials() {
        let attempts = AtomicUsize::new(0);
        let prepare = |_: &TcpSocket| {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        };
        let dial = |_: TcpSocket, _: SocketAddr| {
            attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(io::Error::other("unexpected dial")))
        };
        let error = connect(&["127.0.0.1:1".parse().unwrap()], &prepare, dial)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            NetError::Io {
                stage: "native pre-connect preparation",
                ..
            }
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }
}
