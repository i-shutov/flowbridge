//! Privacy-preserving native packet protocol inventory for explicitly consented
//! LISTEN_ONLY laboratory observation. Counts *port hints*, never DNS queries,
//! process ownership, packets, addresses or payloads. It cannot establish DNS
//! leak freedom, QUIC protection, or selected-application routing.
use crate::ndis_wire::Direction;
use serde_json::{json, Value};

#[derive(Debug, Default)]
pub(crate) struct Profile {
    frames: u64,
    outgoing: u64,
    incoming: u64,
    ipv4: u64,
    ipv6: u64,
    arp: u64,
    other_ethernet: u64,
    malformed_or_truncated: u64,
    ipv4_fragments: u64,
    ipv6_fragments: u64,
    ipv6_extensions: u64,
    tcp: u64,
    udp: u64,
    other_ip_transport: u64,
    tcp_port_53: u64,
    udp_port_53: u64,
    udp53_standard_question_shape: u64,
    udp53_standard_response_shape: u64,
    udp53_unclassified_payload: u64,
    tcp_port_853: u64,
    udp_port_853: u64,
    udp_port_443: u64,
    udp_port_5353: u64,
    udp_port_5355: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DnsWireShape {
    StandardQuestion,
    StandardResponse,
    Unclassified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Tcp(u16, u16),
    Udp(u16, u16, DnsWireShape),
    Fragment,
    Other,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    V4(Transport),
    V6(Transport, bool),
    Arp,
    Other,
    Malformed,
}

fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

// Conservative RFC 1035 first-question wire shape, not DNS transaction
// authentication. No QNAME labels or question contents leave this stack
// frame; compressed first names, nonstandard opcodes and split TCP messages
// intentionally remain unclassified. This is never proof of containment.
fn dns_standard_question_shape(message: &[u8]) -> DnsWireShape {
    if message.len() < 17 {
        return DnsWireShape::Unclassified;
    }
    let flags = be16(message, 2);
    if (flags & 0x7800) != 0 || be16(message, 4) != 1 {
        return DnsWireShape::Unclassified;
    }
    let mut offset = 12;
    let mut encoded_name_len = 1usize;
    loop {
        if offset >= message.len() {
            return DnsWireShape::Unclassified;
        }
        let label_len = usize::from(message[offset]);
        offset += 1;
        if label_len == 0 {
            break;
        }
        // Compression pointers in the first question are not dereferenced.
        if label_len > 63
            || encoded_name_len + label_len + 1 > 255
            || offset + label_len > message.len()
        {
            return DnsWireShape::Unclassified;
        }
        encoded_name_len += label_len + 1;
        offset += label_len;
    }
    if offset + 4 > message.len()
        || be16(message, offset) == 0
        || be16(message, offset + 2) == 0
    {
        return DnsWireShape::Unclassified;
    }
    if (flags & 0x8000) != 0 {
        DnsWireShape::StandardResponse
    } else {
        DnsWireShape::StandardQuestion
    }
}

fn transport(protocol: u8, bytes: &[u8]) -> Transport {
    match protocol {
        6 => {
            if bytes.len() < 20 {
                return Transport::Malformed;
            }
            let header = usize::from(bytes[12] >> 4) * 4;
            if !(20..=60).contains(&header) || header > bytes.len() {
                return Transport::Malformed;
            }
            Transport::Tcp(be16(bytes, 0), be16(bytes, 2))
        }
        17 => {
            if bytes.len() < 8 {
                return Transport::Malformed;
            }
            let datagram_len = usize::from(be16(bytes, 4));
            if datagram_len < 8 || datagram_len > bytes.len() {
                return Transport::Malformed;
            }
            let source = be16(bytes, 0);
            let destination = be16(bytes, 2);
            let shape = if source == 53 || destination == 53 {
                dns_standard_question_shape(&bytes[8..datagram_len])
            } else {
                DnsWireShape::Unclassified
            };
            Transport::Udp(source, destination, shape)
        }
        _ => Transport::Other,
    }
}

fn ipv4(ip: &[u8]) -> Frame {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return Frame::Malformed;
    }
    let header = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(be16(ip, 2));
    if !(20..=60).contains(&header) || total < header || total > ip.len() {
        return Frame::Malformed;
    }
    // MF and nonzero fragment offset both forbid inferring a UDP/TCP port.
    let flags_offset = be16(ip, 6);
    let kind = if flags_offset & 0x3fff != 0 {
        Transport::Fragment
    } else {
        transport(ip[9], &ip[header..total])
    };
    Frame::V4(kind)
}

fn ipv6(ip: &[u8]) -> Frame {
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return Frame::Malformed;
    }
    let payload_len = usize::from(be16(ip, 4));
    // Zero-length jumbograms and ESP are intentionally not parsed as UDP/TCP.
    if payload_len == 0 || payload_len > ip.len() - 40 {
        return Frame::Malformed;
    }
    let end = 40 + payload_len;
    let mut offset = 40;
    let mut next = ip[6];
    let mut extensions = false;
    for _ in 0..8 {
        let len = match next {
            0 | 43 | 60 => {
                if offset + 2 > end {
                    return Frame::Malformed;
                }
                (usize::from(ip[offset + 1]) + 1) * 8
            }
            51 => {
                if offset + 2 > end {
                    return Frame::Malformed;
                }
                (usize::from(ip[offset + 1]) + 2) * 4
            }
            44 => {
                // Even an atomic fragment is counted separately rather than
                // trusting transport ports across fragment-boundary races.
                if offset + 8 > end {
                    return Frame::Malformed;
                }
                return Frame::V6(Transport::Fragment, true);
            }
            _ => break,
        };
        if len < 8 || offset + len > end || offset + len - 40 > 512 {
            return Frame::Malformed;
        }
        next = ip[offset];
        offset += len;
        extensions = true;
    }
    if matches!(next, 0 | 43 | 44 | 51 | 60) {
        return Frame::Malformed;
    }
    Frame::V6(transport(next, &ip[offset..end]), extensions)
}

fn frame(frame: &[u8]) -> Frame {
    if frame.len() < 14 {
        return Frame::Malformed;
    }
    let mut ethertype = be16(frame, 12);
    let mut offset = 14;
    // Exactly two standard VLAN tags; deeper nesting remains unclassified.
    for _ in 0..2 {
        if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if offset + 4 > frame.len() {
            return Frame::Malformed;
        }
        ethertype = be16(frame, offset + 2);
        offset += 4;
    }
    if matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        return Frame::Malformed;
    }
    match ethertype {
        0x0800 => ipv4(&frame[offset..]),
        0x86dd => ipv6(&frame[offset..]),
        0x0806 => Frame::Arp,
        _ => Frame::Other,
    }
}

impl Profile {
    pub(crate) fn observe(&mut self, direction: Direction, data: &[u8]) {
        self.frames += 1;
        match direction {
            Direction::ToAdapter => self.outgoing += 1,
            Direction::ToStack => self.incoming += 1,
        }
        let transport = match frame(data) {
            Frame::V4(t) => {
                self.ipv4 += 1;
                if t == Transport::Fragment {
                    self.ipv4_fragments += 1;
                }
                t
            }
            Frame::V6(t, ext) => {
                self.ipv6 += 1;
                if ext {
                    self.ipv6_extensions += 1;
                }
                if t == Transport::Fragment {
                    self.ipv6_fragments += 1;
                }
                t
            }
            Frame::Arp => {
                self.arp += 1;
                return;
            }
            Frame::Other => {
                self.other_ethernet += 1;
                return;
            }
            Frame::Malformed => {
                self.malformed_or_truncated += 1;
                return;
            }
        };
        match transport {
            Transport::Tcp(a, b) => {
                self.tcp += 1;
                self.tcp_port_53 += u64::from(a == 53 || b == 53);
                self.tcp_port_853 += u64::from(a == 853 || b == 853);
            }
            Transport::Udp(a, b, shape) => {
                self.udp += 1;
                if a == 53 || b == 53 {
                    self.udp_port_53 += 1;
                    match shape {
                        DnsWireShape::StandardQuestion => self.udp53_standard_question_shape += 1,
                        DnsWireShape::StandardResponse => self.udp53_standard_response_shape += 1,
                        DnsWireShape::Unclassified => self.udp53_unclassified_payload += 1,
                    }
                }
                self.udp_port_853 += u64::from(a == 853 || b == 853);
                self.udp_port_443 += u64::from(a == 443 || b == 443);
                self.udp_port_5353 += u64::from(a == 5353 || b == 5353);
                self.udp_port_5355 += u64::from(a == 5355 || b == 5355);
            }
            Transport::Malformed => self.malformed_or_truncated += 1,
            Transport::Other => self.other_ip_transport += 1,
            Transport::Fragment => {}
        }
    }

    pub(crate) fn report(&self) -> Value {
        json!({
            "requested":true, "read_only":true, "packet_payload_saved":false,
            "network_identity_saved":false, "process_identity_saved":false,
            "native_packet_owner_proved":false, "dns_leak_free":false,
            "selected_application_containment_proved":false,
            "classification":"bounded_l2_l3_l4_port_hints_not_dns_transactions",
            "frames":self.frames, "outgoing":self.outgoing, "incoming":self.incoming,
            "ipv4":self.ipv4, "ipv6":self.ipv6, "arp":self.arp,
            "other_ethernet":self.other_ethernet,
            "malformed_or_truncated":self.malformed_or_truncated,
            "ipv4_fragments":self.ipv4_fragments, "ipv6_fragments":self.ipv6_fragments,
            "ipv6_extensions":self.ipv6_extensions, "tcp":self.tcp, "udp":self.udp,
            "other_ip_transport":self.other_ip_transport,
            "tcp_port_53":self.tcp_port_53, "udp_port_53":self.udp_port_53,
            "udp53_standard_question_shape":self.udp53_standard_question_shape,
            "udp53_standard_response_shape":self.udp53_standard_response_shape,
            "udp53_unclassified_payload":self.udp53_unclassified_payload,
            "dns_wire_shape_is_not_dns_transaction_proof":true,
            "tcp_port_853":self.tcp_port_853, "udp_port_853":self.udp_port_853,
            "udp_port_443":self.udp_port_443, "udp_port_5353":self.udp_port_5353,
            "udp_port_5355":self.udp_port_5355,
            "unclassified_dns_over_https":true,
            "cannot_prove_absence_of_unobserved_traffic":true
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0; 12];
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn udp(a: u16, b: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&a.to_be_bytes());
        bytes.extend_from_slice(&b.to_be_bytes());
        bytes.extend_from_slice(&8u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes
    }

    fn ipv4_udp(a: u16, b: u16) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 17;
        ip[2..4].copy_from_slice(&28u16.to_be_bytes());
        ip.extend_from_slice(&udp(a, b));
        ethernet(0x0800, &ip)
    }

    fn ipv6_udp(a: u16, b: u16) -> Vec<u8> {
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&16u16.to_be_bytes());
        ip[6] = 0; // Hop-by-Hop Options, exactly 8 bytes
        ip.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
        ip.extend_from_slice(&udp(a, b));
        ethernet(0x86dd, &ip)
    }

    #[test]
    fn mixed_ipv4_ipv6_vlan_dns_quic_and_privacy_counts() {
        let mut sample = Profile::default();
        sample.observe(Direction::ToAdapter, &ipv4_udp(40000, 53));
        sample.observe(Direction::ToStack, &ipv6_udp(443, 40000));
        let inner = ipv4_udp(5353, 40000);
        let mut vlan = vec![0u8; 12];
        vlan.extend_from_slice(&0x8100u16.to_be_bytes());
        vlan.extend_from_slice(&0u16.to_be_bytes());
        vlan.extend_from_slice(&0x0800u16.to_be_bytes());
        vlan.extend_from_slice(&inner[14..]);
        sample.observe(Direction::ToStack, &vlan);
        let report = sample.report();
        assert_eq!(report["frames"], 3);
        assert_eq!(report["outgoing"], 1);
        assert_eq!(report["incoming"], 2);
        assert_eq!(report["udp"], 3);
        assert_eq!(report["udp_port_53"], 1);
        assert_eq!(report["udp_port_443"], 1);
        assert_eq!(report["udp_port_5353"], 1);
        assert_eq!(report["ipv6_extensions"], 1);
        assert_eq!(report["dns_leak_free"], false);
        assert_eq!(report["native_packet_owner_proved"], false);
        assert!(report.get("addresses").is_none());
        assert!(report.get("ports").is_none());
    }

    #[test]
    fn fragments_short_frames_and_invalid_headers_never_infer_dns_ports() {
        let mut profile = Profile::default();
        let mut fragment = ipv4_udp(40000, 53);
        fragment[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        profile.observe(Direction::ToAdapter, &fragment);
        let mut v6fragment = vec![0u8; 40];
        v6fragment[0] = 0x60;
        v6fragment[4..6].copy_from_slice(&8u16.to_be_bytes());
        v6fragment[6] = 44;
        v6fragment.extend_from_slice(&[17, 0, 0, 1, 0, 0, 0, 1]);
        profile.observe(Direction::ToStack, &ethernet(0x86dd, &v6fragment));
        profile.observe(Direction::ToStack, &[0u8; 8]);
        let mut invalid = ipv4_udp(40000, 53);
        invalid[16..18].copy_from_slice(&0x0001u16.to_be_bytes());
        invalid[16] = 0; // deliberately not relevant to transport
        invalid.truncate(32);
        profile.observe(Direction::ToStack, &invalid);
        let report = profile.report();
        assert_eq!(report["frames"], 4);
        assert_eq!(report["ipv4_fragments"], 1);
        assert_eq!(report["ipv6_fragments"], 1);
        assert_eq!(report["udp_port_53"], 0);
        assert_eq!(report["malformed_or_truncated"], 2);
    }

    fn ipv4_udp_payload(a: u16, b: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = ipv4_udp(a, b);
        frame.extend_from_slice(payload);
        let total_len = u16::try_from(28 + payload.len()).unwrap();
        let udp_len = u16::try_from(8 + payload.len()).unwrap();
        frame[16..18].copy_from_slice(&total_len.to_be_bytes());
        frame[38..40].copy_from_slice(&udp_len.to_be_bytes());
        frame
    }

    fn standard_dns_question() -> Vec<u8> {
        let mut question = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["example", "invalid"] {
            question.push(label.len() as u8);
            question.extend_from_slice(label.as_bytes());
        }
        question.push(0);
        question.extend_from_slice(&[0, 1, 0, 1]);
        question
    }

    #[test]
    fn dns_question_wire_shape_is_distinct_from_port_53_and_keeps_privacy() {
        let mut sample = Profile::default();
        let query = standard_dns_question();
        sample.observe(Direction::ToAdapter, &ipv4_udp_payload(43100, 53, &query));
        let mut response = query.clone();
        response[2] |= 0x80;
        sample.observe(Direction::ToStack, &ipv4_udp_payload(53, 43100, &response));
        // Previous native zero-only UDP/53 canary is not a DNS question.
        sample.observe(Direction::ToAdapter, &ipv4_udp_payload(43100, 53, &[0; 4]));
        let mut invalid_label = query.clone();
        invalid_label[12] = 0xc0;
        sample.observe(
            Direction::ToAdapter,
            &ipv4_udp_payload(43100, 53, &invalid_label),
        );
        let report = sample.report();
        assert_eq!(report["frames"], 4);
        assert_eq!(report["udp_port_53"], 4);
        assert_eq!(report["udp53_standard_question_shape"], 1);
        assert_eq!(report["udp53_standard_response_shape"], 1);
        assert_eq!(report["udp53_unclassified_payload"], 2);
        assert_eq!(report["dns_wire_shape_is_not_dns_transaction_proof"], true);
        assert_eq!(report["native_packet_owner_proved"], false);
        assert_eq!(report["dns_leak_free"], false);
        assert_eq!(report["selected_application_containment_proved"], false);
        for private_key in ["qname", "question", "addresses", "ports", "payload"] {
            assert!(report.get(private_key).is_none());
        }
    }

    #[test]
    fn ipv6_unbounded_extensions_and_udp_length_are_rejected() {
        let mut packet = ipv6_udp(53, 40000);
        packet[14 + 40 + 1] = 255;
        assert_eq!(frame(&packet), Frame::Malformed);
        let mut packet = ipv4_udp(53, 40000);
        packet[14 + 20 + 4] = 0xff;
        assert_eq!(frame(&packet), Frame::V4(Transport::Malformed));
    }
}
