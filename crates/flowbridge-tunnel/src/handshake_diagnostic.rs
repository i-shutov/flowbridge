//! Explicit DIRECT SSH identification A/B diagnostics; not managed tunnel or protected mode.
//! No SSH auth, credentials, endpoint, banner or packet payload in serialized results.
use serde::Serialize;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
const CLIENT: &[u8] = b"SSH-2.0-FlowBridgeProbe_0.2\r\n";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    TcpConnectFailed,
    ServerIdentificationTimeout,
    ServerIdentificationInvalid,
    ServerIdentificationIoFailure,
    ClientIdentificationSendFailed,
    PacketHeaderTimeout,
    PacketHeaderInvalid,
    PacketHeaderIoFailure,
    PacketHeaderObserved,
}
#[derive(Debug, Serialize)]
pub struct Attempt {
    pub mode: &'static str,
    pub outcome: Outcome,
    pub tcp_connected: bool,
    pub server_identification_received: bool,
    pub client_identification_sent: bool,
    pub binary_packet_header_observed: bool,
    pub elapsed_ms: u64,
    pub server_identification_elapsed_ms: Option<u64>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub kind: &'static str,
    pub direct_diagnostic: bool,
    pub authentication_attempted: bool,
    pub endpoint_or_packet_logged: bool,
    pub direct_fallback_attempted: bool,
    pub kex_or_authentication_completed: bool,
    pub workaround_proven: bool,
    pub attempts: [Attempt; 2],
}
fn ms(t: Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}
fn remaining(t: Instant, timeout: Duration) -> io::Result<Duration> {
    timeout
        .checked_sub(t.elapsed())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SSH probe deadline"))
}
fn read_byte(s: &mut TcpStream, t: Instant, timeout: Duration) -> io::Result<u8> {
    s.set_read_timeout(Some(remaining(t, timeout)?))?;
    let mut b = [0];
    s.read_exact(&mut b)?;
    Ok(b[0])
}
fn banner(s: &mut TcpStream, t: Instant, timeout: Duration) -> io::Result<()> {
    for _ in 0..=8 {
        let mut line = Vec::with_capacity(80);
        for _ in 0..255 {
            let b = read_byte(s, t, timeout)?;
            line.push(b);
            if b == b'\n' {
                break;
            }
        }
        if !line.ends_with(b"\r\n")
            || !line[..line.len() - 2]
                .iter()
                .all(|b| (32..=126).contains(b))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid banner line",
            ));
        }
        if line.starts_with(b"SSH-") {
            if line.len() >= 13 && (line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-"))
            {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid identification",
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "too many pre-identification lines",
    ))
}
fn packet_header(s: &mut TcpStream, t: Instant, timeout: Duration) -> io::Result<()> {
    let mut b = [0; 5];
    for v in &mut b {
        *v = read_byte(s, t, timeout)?;
    }
    let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let pad = u32::from(b[4]);
    if !(6..=262_144).contains(&len) || pad < 4 || pad >= len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SSH binary header",
        ));
    }
    Ok(())
}
fn timed_out(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
fn once(addr: SocketAddr, timeout: Duration, first: bool) -> Attempt {
    let t = Instant::now();
    let mut a = Attempt {
        mode: if first {
            "server_first"
        } else {
            "client_first"
        },
        outcome: Outcome::TcpConnectFailed,
        tcp_connected: false,
        server_identification_received: false,
        client_identification_sent: false,
        binary_packet_header_observed: false,
        elapsed_ms: 0,
        server_identification_elapsed_ms: None,
    };
    let mut s = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => {
            a.elapsed_ms = ms(t);
            return a;
        }
    };
    a.tcp_connected = true;
    let send = |s: &mut TcpStream| -> io::Result<()> {
        s.set_write_timeout(Some(remaining(t, timeout)?))?;
        s.write_all(CLIENT)
    };
    if !first {
        if send(&mut s).is_err() {
            a.outcome = Outcome::ClientIdentificationSendFailed;
            a.elapsed_ms = ms(t);
            return a;
        }
        a.client_identification_sent = true;
    }
    if let Err(e) = banner(&mut s, t, timeout) {
        a.outcome = if timed_out(&e) {
            Outcome::ServerIdentificationTimeout
        } else if e.kind() == io::ErrorKind::InvalidData {
            Outcome::ServerIdentificationInvalid
        } else {
            Outcome::ServerIdentificationIoFailure
        };
        a.elapsed_ms = ms(t);
        return a;
    }
    a.server_identification_received = true;
    a.server_identification_elapsed_ms = Some(ms(t));
    if first {
        if send(&mut s).is_err() {
            a.outcome = Outcome::ClientIdentificationSendFailed;
            a.elapsed_ms = ms(t);
            return a;
        }
        a.client_identification_sent = true;
    }
    a.outcome = match packet_header(&mut s, t, timeout) {
        Ok(()) => {
            a.binary_packet_header_observed = true;
            Outcome::PacketHeaderObserved
        }
        Err(e) if timed_out(&e) => Outcome::PacketHeaderTimeout,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Outcome::PacketHeaderInvalid,
        Err(_) => Outcome::PacketHeaderIoFailure,
    };
    a.elapsed_ms = ms(t);
    a
}
/// Explicit CLI-only DIRECT TCP probe. Never called by supervisor or packet worker.
/// Caller must enforce exact consent and 100..=10000 ms; DNS is not performed.
pub fn compare_direct(addr: SocketAddr, timeout: Duration) -> Report {
    Report {
        kind: "ssh_identification_order_ab",
        direct_diagnostic: true,
        authentication_attempted: false,
        endpoint_or_packet_logged: false,
        direct_fallback_attempted: false,
        kex_or_authentication_completed: false,
        workaround_proven: false,
        attempts: [once(addr, timeout, true), once(addr, timeout, false)],
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};
    const BANNER: &[u8] = b"SSH-2.0-TestServer_1\r\n";
    fn client(s: &mut TcpStream) {
        for expected in CLIENT {
            let mut one = [0];
            s.read_exact(&mut one).unwrap();
            assert_eq!(one[0], *expected);
        }
    }
    #[test]
    fn real_loopback_two_orders_and_valid_binary_header() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = thread::spawn(move || {
            for i in 0..2 {
                let (mut s, _) = l.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                if i == 0 {
                    s.write_all(BANNER).unwrap();
                    client(&mut s);
                } else {
                    client(&mut s);
                    s.write_all(BANNER).unwrap();
                }
                s.write_all(&[0, 0, 0, 12, 8]).unwrap();
            }
        });
        let r = compare_direct(addr, Duration::from_secs(2));
        t.join().unwrap();
        assert!(r
            .attempts
            .iter()
            .all(|a| a.outcome == Outcome::PacketHeaderObserved));
        assert!(!r.workaround_proven);
    }
    #[test]
    fn real_loopback_server_first_only_stall_not_masked() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(BANNER).unwrap();
            client(&mut s);
            s.write_all(&[0, 0, 0, 12, 8]).unwrap();
            let (mut s, _) = l.accept().unwrap();
            client(&mut s);
            thread::sleep(Duration::from_millis(220));
        });
        let r = compare_direct(addr, Duration::from_millis(110));
        t.join().unwrap();
        assert_eq!(r.attempts[0].outcome, Outcome::PacketHeaderObserved);
        assert_eq!(r.attempts[1].outcome, Outcome::ServerIdentificationTimeout);
        assert!(!r.direct_fallback_attempted);
    }
    #[test]
    fn overlong_banner_does_not_send_server_first_client_identification() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = l.accept().unwrap();
                s.write_all(&[b'A'; 256]).unwrap();
                s.write_all(b"\r\n").unwrap();
            }
        });
        let r = compare_direct(addr, Duration::from_millis(500));
        t.join().unwrap();
        assert_eq!(r.attempts[0].outcome, Outcome::ServerIdentificationInvalid);
        assert!(!r.attempts[0].client_identification_sent);
    }
}