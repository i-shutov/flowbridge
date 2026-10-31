//! Controlled native TCP reflection experiment, NOT arbitrary-app protection.
//! The Windows entrypoint creates and retains the selected socket itself. An
//! IP Helper snapshot alone cannot create this authority or a PacketBound token.
//! Both client and relay outbound packets are reflected UP to the local stack;
//! modified frames can never be emitted to the physical adapter by this module.

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use crate::ndis_session::LabDisposition;
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use crate::ndis_wire::{Direction, PacketView};
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use flowbridge_core::ndis_ethernet::{inspect_l2_ip, IpVersion};
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use flowbridge_core::ndis_frame_tcp::rewrite_ethernet_tcp_tuple;
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use flowbridge_core::tcp_packet::{inspect_tcp, TcpTuple};
use serde::Deserialize;
use serde_json::Value;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub adapter_name: String,
    pub local_ipv4: Ipv4Addr,
    pub target: SocketAddrV4,
    pub upstream: SocketAddr,
    pub consent: String,
    pub duration_ms: u64,
    #[serde(default)]
    pub expect_denied: bool,
}

impl Request {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.consent != "NATIVE_SELF_SOCKET_TCP_REFLECT"
            || !(2000..=15000).contains(&self.duration_ms)
            || self.adapter_name.is_empty() || self.adapter_name.len() > 255
            || !self.adapter_name.bytes().all(|b| b.is_ascii_graphic())
            || self.local_ipv4.is_unspecified() || self.local_ipv4.is_loopback()
            || self.local_ipv4.is_multicast() || self.local_ipv4.is_broadcast()
            || self.target.ip().is_unspecified() || self.target.ip().is_loopback()
            || self.target.ip().is_multicast() || self.target.ip().is_broadcast()
            || self.target.ip() == &self.local_ipv4 || self.target.port() != 80
            || !self.upstream.ip().is_loopback() || self.upstream.port() == 0
        {
            return Err("Requires explicit bounded IPv4 self-socket HTTP canary consent; no protected mode".into());
        }
        Ok(())
    }
}

pub fn run(request: Request) -> Result<Value, String> {
    request.validate()?;
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        crate::windows_self_redirect::run(request)
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    {
        Err("Native self-socket reflection requires Windows x64".into())
    }
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
#[derive(Default, Debug)]
pub(crate) struct Counters {
    pub client_reflected: u64,
    pub relay_reflected: u64,
    pub selected_dropped: u64,
    pub checksums_or_options_rejected: u64,
    pub unsolicited_wire_replies_dropped: u64,
    pub owner_checked: bool,
}

/// This state is exclusively for a socket created/held by the calling process.
/// Its expected owner is never supplied through JSON or inferred from a name.
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
pub(crate) struct Reflection {
    pub original: TcpTuple,
    pub ingress: SocketAddr,
    pub peer: SocketAddr,
    pub counters: Counters,
    initial_sequence: Option<u32>,
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
impl Reflection {
    pub fn new(original: TcpTuple, ingress: SocketAddr) -> Result<Self, String> {
        if !original.source.is_ipv4() || !original.destination.is_ipv4() || !ingress.is_ipv4()
            || original.source.ip() != ingress.ip() || original.source.port() == 0
            || original.destination.port() == 0 || ingress.port() == 0
            || original.source == ingress || original.source.ip() == original.destination.ip()
        {
            return Err("Invalid independently reserved native reflection endpoints".into());
        }
        Ok(Self {
            original, ingress,
            peer: SocketAddr::new(original.destination.ip(), original.source.port()),
            counters: Counters::default(), initial_sequence: None,
        })
    }

    /// A conservative pre-check identifies candidate ports BEFORE validating
    /// checksums; a selected checksum/offload failure must not escape DIRECT.
    pub fn decide(
        &mut self,
        packet: &PacketView<'_>,
        owned_socket_check: &mut impl FnMut() -> bool,
    ) -> LabDisposition {
        let frame = packet.frame;
        let Some(tuple) = candidate_tuple(frame) else { return LabDisposition::Original; };
        let response = TcpTuple { source: self.ingress, destination: self.peer };
        let original_reply = TcpTuple { source: self.original.destination, destination: self.original.source };
        if packet.direction == Direction::ToStack && tuple == original_reply {
            self.counters.unsolicited_wire_replies_dropped += 1;
            return LabDisposition::Drop;
        }
        if packet.direction != Direction::ToAdapter || (tuple != self.original && tuple != response) {
            return LabDisposition::Original;
        }
        let Ok(region) = inspect_l2_ip(frame) else {
            self.counters.selected_dropped += 1;
            return LabDisposition::Drop;
        };
        if region.version != IpVersion::V4 {
            self.counters.selected_dropped += 1;
            return LabDisposition::Drop;
        }
        let ip = &frame[region.offset..region.offset + region.length];
        let header_len = usize::from(ip[0] & 15) * 4;
        let Ok(checked) = inspect_tcp(ip) else {
            self.counters.checksums_or_options_rejected += 1;
            self.counters.selected_dropped += 1;
            return LabDisposition::Drop;
        };
        if packet.vlan_metadata != 0 || !owned_socket_check() {
            self.counters.selected_dropped += 1;
            return LabDisposition::Drop;
        }
        let flags = ip[header_len + 13];
        let sequence = u32::from_be_bytes(ip[header_len + 4..header_len + 8].try_into().unwrap());
        if tuple == self.original {
            match self.initial_sequence {
                None if flags & 0x17 == 0x02 && checked.data_bytes == 0 => {
                    self.initial_sequence = Some(sequence);
                    self.counters.owner_checked = true;
                }
                None => {
                    self.counters.selected_dropped += 1;
                    return LabDisposition::Drop;
                }
                Some(initial) if flags & 0x02 != 0 && sequence != initial => {
                    self.counters.selected_dropped += 1;
                    return LabDisposition::Drop;
                }
                _ => {}
            }
        } else if self.initial_sequence.is_none() {
            self.counters.selected_dropped += 1;
            return LabDisposition::Drop;
        }
        let target = if tuple == self.original {
            TcpTuple { source: self.peer, destination: self.ingress }
        } else { original_reply };
        let mut reflected = frame.to_vec();
        let mut scratch = vec![0u8; crate::ndis_wire::MAX_FRAME_BYTES];
        if rewrite_ethernet_tcp_tuple(&mut reflected, &mut scratch, tuple, target).is_err() {
            self.counters.selected_dropped += 1;
            return LabDisposition::Drop;
        }
        // Reverse link direction too: local source MAC becomes destination.
        for i in 0..6 { reflected.swap(i, i + 6); }
        if tuple == self.original { self.counters.client_reflected += 1; }
        else { self.counters.relay_reflected += 1; }
        LabDisposition::ToStack(reflected)
    }
}

/// Only classify a potential selected flow here. Declared lengths/checksums
/// are deliberately NOT trusted for classification; they are validated later.
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
fn candidate_tuple(frame: &[u8]) -> Option<TcpTuple> {
    if frame.len() < 14 { return None; }
    let mut offset = 14;
    let mut ether = u16::from_be_bytes([frame[12], frame[13]]);
    for _ in 0..2 {
        if ether != 0x8100 && ether != 0x88a8 { break; }
        if frame.len() < offset + 4 { return None; }
        ether = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    if ether != 0x0800 || frame.len() < offset + 20 { return None; }
    let ip = &frame[offset..];
    if ip[0] >> 4 != 4 || ip[9] != 6 { return None; }
    let h = usize::from(ip[0] & 15) * 4;
    if h < 20 || ip.len() < h + 4 { return None; }
    Some(TcpTuple {
        source: SocketAddr::new(Ipv4Addr::new(ip[12],ip[13],ip[14],ip[15]).into(),u16::from_be_bytes([ip[h],ip[h+1]])),
        destination: SocketAddr::new(Ipv4Addr::new(ip[16],ip[17],ip[18],ip[19]).into(),u16::from_be_bytes([ip[h+2],ip[h+3]])),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) { sum += (u32::from(chunk[0]) << 8) + u32::from(*chunk.get(1).unwrap_or(&0)); }
        while sum > 65535 { sum = (sum & 65535) + (sum >> 16); }
        !(sum as u16)
    }
    fn reflection() -> Reflection {
        Reflection::new(TcpTuple {
            source: "192.0.2.10:51000".parse().unwrap(),
            destination: "198.51.100.10:80".parse().unwrap(),
        }, "192.0.2.10:52000".parse().unwrap()).unwrap()
    }
    fn frame(tuple: TcpTuple, flags: u8, seq: u32) -> Vec<u8> {
        let mut f = vec![0u8; 54];
        f[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        f[12..14].copy_from_slice(&[8, 0]);
        let ip = &mut f[14..];
        ip[0] = 0x45; ip[2..4].copy_from_slice(&40u16.to_be_bytes()); ip[8] = 64; ip[9] = 6;
        if let (SocketAddr::V4(a), SocketAddr::V4(b)) = (tuple.source, tuple.destination) {
            ip[12..16].copy_from_slice(&a.ip().octets()); ip[16..20].copy_from_slice(&b.ip().octets());
        } else { panic!("fixture must be IPv4"); }
        ip[20..22].copy_from_slice(&tuple.source.port().to_be_bytes());
        ip[22..24].copy_from_slice(&tuple.destination.port().to_be_bytes());
        ip[24..28].copy_from_slice(&seq.to_be_bytes()); ip[32] = 0x50; ip[33] = flags;
        let mut pseudo = ip[12..20].to_vec(); pseudo.extend_from_slice(&[0, 6, 0, 20]); pseudo.extend_from_slice(&ip[20..]);
        ip[36..38].copy_from_slice(&checksum(&pseudo).to_be_bytes());
        let h = checksum(&ip[..20]); ip[10..12].copy_from_slice(&h.to_be_bytes());
        f
    }
    fn packet(f: &[u8]) -> PacketView<'_> { PacketView {direction: Direction::ToAdapter, ndis_flags:0, vlan_metadata:0, filter_id:0, frame:f} }
    #[test]
    fn request_cannot_enable_protected_or_remote_proxy() {
        let mut r = Request {adapter_name:"a".into(), local_ipv4:"192.0.2.10".parse().unwrap(), target:"198.51.100.10:80".parse().unwrap(), upstream:"127.0.0.1:1080".parse().unwrap(), consent:"NATIVE_SELF_SOCKET_TCP_REFLECT".into(), duration_ms:5000, expect_denied:false};
        assert!(r.validate().is_ok()); r.upstream="192.0.2.7:1080".parse().unwrap(); assert!(r.validate().is_err());
        r.upstream="127.0.0.1:1080".parse().unwrap(); r.consent.clear(); assert!(r.validate().is_err());
    }
    #[test]
    fn native_reflection_has_bidirectional_exact_tuple_and_swapped_mac() {
        let mut r=reflection(); let syn=frame(r.original,2,1); let before=syn.clone();
        let LabDisposition::ToStack(forward)=r.decide(&packet(&syn), &mut || true) else {panic!("SYN not reflected")};
        assert_eq!(syn,before); assert_eq!(&forward[..6], &syn[6..12]);
        assert_eq!(inspect_tcp(&forward[14..]).unwrap().tuple, TcpTuple {source:r.peer,destination:r.ingress});
        let reply=frame(TcpTuple {source:r.ingress,destination:r.peer},0x12,10);
        let LabDisposition::ToStack(back)=r.decide(&packet(&reply), &mut || true) else {panic!("return not reflected")};
        assert_eq!(inspect_tcp(&back[14..]).unwrap().tuple,TcpTuple {source:r.original.destination,destination:r.original.source});
        assert_eq!((r.counters.client_reflected,r.counters.relay_reflected),(1,1));
    }
    #[test]
    fn absent_owner_checksum_bad_and_reused_syn_never_pass_original() {
        let mut r=reflection(); let syn=frame(r.original,2,3);
        assert!(matches!(r.decide(&packet(&syn), &mut || false),LabDisposition::Drop));
        let mut bad=syn.clone(); bad[50]^=1;
        assert!(matches!(r.decide(&packet(&bad), &mut || true),LabDisposition::Drop));
        let mut truncated=syn.clone(); truncated.truncate(40);
        assert!(matches!(r.decide(&packet(&truncated), &mut || true),LabDisposition::Drop));
        let mut trailer=syn.clone(); trailer.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(r.decide(&packet(&trailer), &mut || true),LabDisposition::Drop));
        assert!(matches!(r.decide(&packet(&syn), &mut || true),LabDisposition::ToStack(_)));
        let reused=frame(r.original,2,4);
        assert!(matches!(r.decide(&packet(&reused), &mut || true),LabDisposition::Drop));
    }
    #[test]
    fn unrelated_flow_unchanged_and_wire_reply_cannot_bypass_local_relay() {
        let mut r=reflection(); let other=frame(TcpTuple {source:"192.0.2.10:53000".parse().unwrap(),..r.original},2,1);
        assert!(matches!(r.decide(&packet(&other), &mut || panic!("unselected owner queried")),LabDisposition::Original));
        let wire=frame(TcpTuple {source:r.original.destination,destination:r.original.source},0x12,5);
        let mut inbound=packet(&wire); inbound.direction=Direction::ToStack;
        assert!(matches!(r.decide(&inbound,&mut || true),LabDisposition::Drop));
        assert_eq!(r.counters.unsolicited_wire_replies_dropped,1);
    }
    #[test]
    fn data_before_syn_and_unknown_vlan_metadata_fail_closed() {
        let mut r=reflection();let ack=frame(r.original,0x10,4);
        assert!(matches!(r.decide(&packet(&ack),&mut || true),LabDisposition::Drop));
        let syn=frame(r.original,2,1);let mut vlan=packet(&syn);vlan.vlan_metadata=1;
        assert!(matches!(r.decide(&vlan,&mut || true),LabDisposition::Drop));
    }
}
