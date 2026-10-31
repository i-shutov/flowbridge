//! Explicit, consented, binary-transparent SSH server-banner-first bridge.
//! Only suitable as a separately invoked OpenSSH ProxyCommand. This does NOT
//! establish authentication, native packet ownership or protected fail-closed.
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn identification(stream: &mut TcpStream, timeout: Duration) -> io::Result<Vec<u8>> {
    let started = Instant::now();
    let mut received = Vec::new();
    for _ in 0..=8 {
        let mut line = Vec::new();
        loop {
            if line.len() >= 255 {
                return Err(invalid("SSH banner line exceeds 255 bytes"));
            }
            let remaining = timeout
                .checked_sub(started.elapsed())
                .filter(|value| !value.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SSH banner timeout"))?;
            stream.set_read_timeout(Some(remaining))?;
            let mut byte = [0u8];
            stream.read_exact(&mut byte)?;
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        if !line.ends_with(b"\r\n")
            || !line[..line.len() - 2]
                .iter()
                .all(|byte| (32..=126).contains(byte))
        {
            return Err(invalid("Invalid SSH pre-identification line"));
        }
        let is_ssh = line.starts_with(b"SSH-");
        if is_ssh && !(line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-")) {
            return Err(invalid("Unsupported SSH identification"));
        }
        received.extend_from_slice(&line);
        if is_ssh {
            if line.len() < 13 {
                return Err(invalid("Truncated SSH identification"));
            }
            return Ok(received);
        }
    }
    Err(invalid("Too many SSH pre-identification lines"))
}

/// Server identification is fully verified before the first client byte is
/// read from stdin. Once admitted, both raw byte streams are forwarded
/// unchanged, including KEX and authentication material, with half-close.
pub fn run(endpoint: SocketAddr, timeout: Duration) -> io::Result<()> {
    if endpoint.port() == 0
        || !(Duration::from_millis(100)..=Duration::from_secs(10)).contains(&timeout)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid SSH banner gate parameters",
        ));
    }
    let mut remote = TcpStream::connect_timeout(&endpoint, timeout)?;
    let preamble = identification(&mut remote, timeout)?;
    let stdout = io::stdout();
    let mut outbound = stdout.lock();
    outbound.write_all(&preamble)?;
    outbound.flush()?;
    remote.set_read_timeout(None)?;
    let mut to_remote = remote.try_clone()?;
    let _writer = std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut inbound = stdin.lock();
        let _ = io::copy(&mut inbound, &mut to_remote);
        let _ = to_remote.shutdown(Shutdown::Write);
    });
    io::copy(&mut remote, &mut outbound)?;
    outbound.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    #[test]
    fn banner_does_not_consume_following_binary_packet() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.write_all(b"Notice\r\nSSH-2.0-VerifiedFixture\r\n\x00\x00\x00\x10")
                .unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let got = identification(&mut client, Duration::from_secs(2)).unwrap();
        assert_eq!(got, b"Notice\r\nSSH-2.0-VerifiedFixture\r\n");
        let mut binary = [0u8; 4];
        client.read_exact(&mut binary).unwrap();
        assert_eq!(binary, [0, 0, 0, 16]);
        server.join().unwrap();
    }

    #[test]
    fn rejects_invalid_server_version() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.write_all(b"SSH-9.0-Invalid\r\n").unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        assert_eq!(
            identification(&mut client, Duration::from_secs(2))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        server.join().unwrap();
    }
}
