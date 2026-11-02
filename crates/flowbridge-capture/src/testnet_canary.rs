//! One bounded, explicit, copy-only NDISRD observation of two fixed
//! TEST-NET IPv4 UDP high-port canaries. Port agreement is NOT process identity.
//! No addresses, ports, paths, PIDs, payloads, or packet bytes are reported.
use crate::ndis_wire::Direction;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::Duration;

const TARGET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);
const SEND_CONSENT: &str = "SEND_TWO_TESTNET_UDP_CANARY_DATAGRAMS";

#[derive(Default)]
pub(crate) struct Canary {
    ports: Option<[u16; 2]>,
    frames_seen: u64,
    matching_first: u64,
    matching_second: u64,
    invalid_or_unsupported: u64,
    nonmatching: u64,
}

impl Canary {
    pub(crate) fn new(ports: Option<[u16; 2]>) -> Self {
        Self {
            ports,
            ..Self::default()
        }
    }

    pub(crate) fn observe(&mut self, direction: Direction, frame: &[u8]) {
        self.frames_seen = self.frames_seen.saturating_add(1);
        let Some([first, second]) = self.ports else {
            return;
        };
        if direction != Direction::ToAdapter {
            self.nonmatching = self.nonmatching.saturating_add(1);
            return;
        }
        let mut offset = 14usize;
        if frame.len() < offset {
            self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
            return;
        }
        let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        for _ in 0..2 {
            if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                break;
            }
            if frame.len() < offset + 4 {
                self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
                return;
            }
            ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
            offset += 4;
        }
        if ethertype != 0x0800 || frame.len() < offset + 20 {
            self.nonmatching = self.nonmatching.saturating_add(1);
            return;
        }
        let ip = &frame[offset..];
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        if ip[0] >> 4 != 4 || !(20..=60).contains(&ihl) || total < ihl + 8 || total > ip.len() {
            self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
            return;
        }
        // Fragmented datagrams cannot reliably supply a transport-port oracle.
        if ip[9] != 17
            || ip[16..20] != TARGET.octets()
            || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
        {
            self.nonmatching = self.nonmatching.saturating_add(1);
            return;
        }
        let udp = &ip[ihl..total];
        let length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        if length < 8 || length > udp.len() {
            self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
            return;
        }
        let destination = u16::from_be_bytes([udp[2], udp[3]]);
        if destination == first {
            self.matching_first = self.matching_first.saturating_add(1);
        } else if destination == second {
            self.matching_second = self.matching_second.saturating_add(1);
        } else {
            self.nonmatching = self.nonmatching.saturating_add(1);
        }
    }

    pub(crate) fn report(&self) -> Value {
        json!({
            "requested": self.ports.is_some(),
            "mode":"NDISRD_LISTEN_BOTH_fixed_TESTNET_UDP4_copy_only",
            "frames_seen":self.frames_seen,
            "first_canary_outgoing_frames":self.matching_first,
            "second_canary_outgoing_frames":self.matching_second,
            "invalid_or_unsupported":self.invalid_or_unsupported,
            "other_frames":self.nonmatching,
            "canary_port_is_not_process_identity":true,
            "packet_to_pid_proven":false,
            "wfp_ndisrd_ordering_proven":false,
            "protected_fail_closed":false,
            "dns_leak_free":false,
            "win10_11_accepted":false,
            "release_accepted":false,
            "identities_endpoints_payloads_saved":false
        })
    }
}

/// A test-only outbound canary emitted from the running EXE image. Real packet
/// receipt must be independently established by NDISRD LISTEN-only QA. UDP
/// send() success does not mean the datagram left the NIC or reached a server.
pub fn send_two(port: u16, consent: &str) -> Result<Value, String> {
    if consent != SEND_CONSENT || !(49_152..=65_534).contains(&port) {
        return Err("Explicit fixed TEST-NET UDP canary consent and high port required".into());
    }
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|_| "TEST-NET UDP canary local socket unavailable")?;
    socket
        .connect((TARGET, port))
        .map_err(|_| "TEST-NET UDP canary route unavailable")?;
    for _ in 0..2 {
        if socket
            .send(b"FB-QA-UDP")
            .map_err(|_| "TEST-NET UDP canary blocked")?
            != 9
        {
            return Err("TEST-NET UDP canary partial send".into());
        }
        std::thread::sleep(Duration::from_millis(120));
    }
    Ok(json!({
        "ok":true,"datagrams_submitted":2,"target_fixed_documentation_network":true,
        "datagrams_observed_on_wire":false,"packet_to_pid_proven":false,
        "protected_fail_closed":false,"release_accepted":false
    }))
}


/// Bounded outbound IPv4 TCP SYN observer for a *separate* WFP/NDISRD
/// ordering canary. A matching port is not a PID, creation epoch, or ownership
/// proof. The observer cannot divert, reinject, or authorize a flow.
#[derive(Default)]
pub(crate) struct TcpSynCanary {
    ports: Option<[u16; 2]>,
    frames_seen: u64,
    first_syn_frames: u64,
    second_syn_frames: u64,
    invalid_or_unsupported: u64,
    nonmatching: u64,
}

impl TcpSynCanary {
    pub(crate) fn new(ports: Option<[u16; 2]>) -> Self {
        Self {
            ports,
            ..Self::default()
        }
    }

    pub(crate) fn observe(&mut self, direction: Direction, frame: &[u8]) {
        self.frames_seen = self.frames_seen.saturating_add(1);
        let Some([first, second]) = self.ports else {
            return;
        };
        if direction != Direction::ToAdapter {
            self.nonmatching = self.nonmatching.saturating_add(1);
            return;
        }
        if frame.len() < 14 {
            self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
            return;
        }
        let mut offset = 14usize;
        let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        for _ in 0..2 {
            if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                break;
            }
            if frame.len() < offset + 4 {
                self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
                return;
            }
            ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
            offset += 4;
        }
        if ethertype != 0x0800 || frame.len() < offset + 20 {
            self.nonmatching = self.nonmatching.saturating_add(1);
            return;
        }
        let ip = &frame[offset..];
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        if ip[0] >> 4 != 4
            || !(20..=60).contains(&ihl)
            || total < ihl + 20
            || total > ip.len()
        {
            self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
            return;
        }
        if ip[9] != 6
            || ip[16..20] != TARGET.octets()
            || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
        {
            self.nonmatching = self.nonmatching.saturating_add(1);
            return;
        }
        let tcp = &ip[ihl..total];
        let tcp_header = usize::from(tcp[12] >> 4) * 4;
        if !(20..=60).contains(&tcp_header) || tcp_header > tcp.len() {
            self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
            return;
        }
        // New connection SYN without ACK, never count an ACK, RST, response,
        // non-initial fragment, or unrelated protocol as a positive baseline.
        if tcp[13] & 0x12 != 0x02 {
            self.nonmatching = self.nonmatching.saturating_add(1);
            return;
        }
        let destination = u16::from_be_bytes([tcp[2], tcp[3]]);
        if destination == first {
            self.first_syn_frames = self.first_syn_frames.saturating_add(1);
        } else if destination == second {
            self.second_syn_frames = self.second_syn_frames.saturating_add(1);
        } else {
            self.nonmatching = self.nonmatching.saturating_add(1);
        }
    }

    pub(crate) fn report(&self) -> Value {
        json!({
            "requested":self.ports.is_some(),
            "mode":"NDISRD_LISTEN_BOTH_fixed_TESTNET_TCP4_SYN_copy_only",
            "frames_seen":self.frames_seen,
            "first_canary_outgoing_syn_frames":self.first_syn_frames,
            "second_canary_outgoing_syn_frames":self.second_syn_frames,
            "invalid_or_unsupported":self.invalid_or_unsupported,
            "other_frames":self.nonmatching,
            "canary_port_is_not_process_identity":true,
            "packet_to_pid_proven":false,
            "wfp_ndisrd_ordering_proven":false,
            "protected_fail_closed":false,
            "dns_leak_free":false,
            "win10_11_accepted":false,
            "release_accepted":false,
            "identities_endpoints_payloads_saved":false
        })
    }
}

/// Submit exactly one bounded TCP connect attempt to an RFC 5737 documentation
/// destination, with NO DNS lookup, application data, or DIRECT retry.
/// Connect may be refused/timed out, especially under WFP DENY: this merely
/// reports that the socket call was attempted. Actual SYN receipt and denial
/// require independently measured native driver positive/negative controls.
pub fn send_one_tcp_syn(port: u16, consent: &str) -> Result<Value, String> {
    if consent != "SEND_ONE_TESTNET_TCP_SYN_CANARY" || !(49_152..=65_534).contains(&port) {
        return Err("Explicit fixed TEST-NET TCP SYN consent and high port required".into());
    }
    let target = SocketAddr::V4(SocketAddrV4::new(TARGET, port));
    let result = TcpStream::connect_timeout(&target, Duration::from_millis(900));
    drop(result);
    Ok(json!({
        "ok":true, "connect_attempt_submitted":true,
        "target_fixed_documentation_network":true,
        "connection_established_claimed":false,
        "syn_observed_by_driver":false,
        "packet_to_pid_proven":false,
        "protected_fail_closed":false, "release_accepted":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(port: u16, tags: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; 12];
        let typ: u16 = if tags == 0 { 0x0800 } else { 0x8100 };
        bytes.extend_from_slice(&typ.to_be_bytes());
        for index in 0..tags {
            bytes.extend_from_slice(&0u16.to_be_bytes());
            let typ: u16 = if index + 1 == tags { 0x0800 } else { 0x8100 };
            bytes.extend_from_slice(&typ.to_be_bytes());
        }
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&37u16.to_be_bytes());
        ip[9] = 17;
        ip[16..20].copy_from_slice(&TARGET.octets());
        bytes.extend_from_slice(&ip);
        bytes.extend_from_slice(&60000u16.to_be_bytes());
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes.extend_from_slice(&17u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(b"FB-QA-UDP");
        bytes
    }

    #[test]
    fn two_distinct_ports_vlans_direction_and_privacy() {
        let mut sample = Canary::new(Some([60021, 60022]));
        sample.observe(Direction::ToAdapter, &frame(60021, 0));
        sample.observe(Direction::ToAdapter, &frame(60022, 2));
        sample.observe(Direction::ToStack, &frame(60021, 0));
        sample.observe(Direction::ToAdapter, &frame(60023, 0));
        let r = sample.report();
        assert_eq!(r["first_canary_outgoing_frames"], 1);
        assert_eq!(r["second_canary_outgoing_frames"], 1);
        assert_eq!(r["other_frames"], 2);
        assert_eq!(r["packet_to_pid_proven"], false);
        assert_eq!(r["wfp_ndisrd_ordering_proven"], false);
        for private in ["60021", "60022", "198.51.100", "FB-QA-UDP"] {
            assert!(!r.to_string().contains(private));
        }
    }

    #[test]
    fn fragmentation_wrong_destination_truncation_never_matches() {
        let mut sample = Canary::new(Some([60021, 60022]));
        let mut fragment = frame(60021, 0);
        fragment[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        sample.observe(Direction::ToAdapter, &fragment);
        let mut wrong = frame(60021, 0);
        wrong[30..34].copy_from_slice(&[203, 0, 113, 53]);
        sample.observe(Direction::ToAdapter, &wrong);
        sample.observe(Direction::ToAdapter, &[0; 13]);
        let r = sample.report();
        assert_eq!(r["first_canary_outgoing_frames"], 0);
        assert_eq!(r["invalid_or_unsupported"], 1);
        assert_eq!(r["other_frames"], 2);
        assert!(send_two(53, SEND_CONSENT).is_err());
        assert!(send_two(60021, "BAD_CONSENT").is_err());
    }

    fn tcp_frame(port: u16, tags: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; 12];
        bytes.extend_from_slice(&(if tags == 0 { 0x0800u16 } else { 0x8100u16 }).to_be_bytes());
        for index in 0..tags {
            bytes.extend_from_slice(&0u16.to_be_bytes());
            bytes.extend_from_slice(&(if index + 1 == tags { 0x0800u16 } else { 0x8100u16 }).to_be_bytes());
        }
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[9] = 6;
        ip[16..20].copy_from_slice(&TARGET.octets());
        bytes.extend_from_slice(&ip);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&43000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&port.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        bytes.extend_from_slice(&tcp);
        bytes
    }

    #[test]
    fn tcp_syn_bounded_canaries_never_promote_port_to_owner() {
        let mut sample = TcpSynCanary::new(Some([60021, 60022]));
        sample.observe(Direction::ToAdapter, &tcp_frame(60021, 0));
        sample.observe(Direction::ToAdapter, &tcp_frame(60022, 2));
        sample.observe(Direction::ToStack, &tcp_frame(60021, 0));
        sample.observe(Direction::ToAdapter, &tcp_frame(60023, 0));
        let mut ack = tcp_frame(60021, 0);
        ack[14 + 20 + 13] = 0x12;
        sample.observe(Direction::ToAdapter, &ack);
        let mut fragment = tcp_frame(60021, 0);
        fragment[14 + 6..14 + 8].copy_from_slice(&0x2000u16.to_be_bytes());
        sample.observe(Direction::ToAdapter, &fragment);
        let mut wrong_destination = tcp_frame(60021, 0);
        wrong_destination[14 + 16..14 + 20].copy_from_slice(&[203, 0, 113, 53]);
        sample.observe(Direction::ToAdapter, &wrong_destination);
        let mut short_header = tcp_frame(60021, 0);
        short_header[14 + 20 + 12] = 0x10;
        sample.observe(Direction::ToAdapter, &short_header);
        let r = sample.report();
        assert_eq!(r["first_canary_outgoing_syn_frames"], 1);
        assert_eq!(r["second_canary_outgoing_syn_frames"], 1);
        assert_eq!(r["invalid_or_unsupported"], 1);
        assert_eq!(r["other_frames"], 5);
        assert_eq!(r["packet_to_pid_proven"], false);
        assert_eq!(r["wfp_ndisrd_ordering_proven"], false);
        for secret in ["60021", "60022", "198.51.100", "43000"] {
            assert!(!r.to_string().contains(secret));
        }
        assert!(send_one_tcp_syn(53, "SEND_ONE_TESTNET_TCP_SYN_CANARY").is_err());
        assert!(send_one_tcp_syn(60021, "BAD_CONSENT").is_err());
    }
}
