//! Checked, in-memory TCP packet inspection and tuple rewrite for a future
//! Windows Packet Filter (NDISRD) Rust worker.
//!
//! Input is a complete IP packet, without Ethernet/VLAN headers. No real
//! driver I/O, flow ownership, redirect, service or injection is implemented.
//! Unsupported packets must be BLOCKED by a protected-mode caller, never
//! silently forwarded unchanged or switched to DIRECT.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpTuple {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    Truncated,
    LengthMismatch,
    Unsupported,
    Checksum,
    InvalidPort,
    TupleMismatch,
    AddressFamilyMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPacket {
    pub tuple: TcpTuple,
    pub tcp_bytes: usize,
    pub data_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

struct Parsed {
    packet: TcpPacket,
    family: Family,
    tcp_start: usize,
}

fn word_sum(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let high = u32::from(pair[0]) << 8;
        let low = pair.get(1).map_or(0, |value| u32::from(*value));
        sum += high + low;
    }
    sum
}

fn finish_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_sum(ip: &[u8], family: Family, tcp_len: usize) -> u32 {
    match family {
        Family::V4 => word_sum(&ip[12..20]) + 6 + tcp_len as u32,
        Family::V6 => {
            let len = tcp_len as u32;
            word_sum(&ip[8..40]) + (len >> 16) + (len & 0xffff) + 6
        }
    }
}

/// Conservatively accept only TCP options whose wire meaning survives a
/// four-tuple rewrite. Authenticated, multipath, experimental and unrecognised
/// options are not safe to transparently rewrite without protocol-specific
/// handling. Header bounds are verified by parse() before this function.
fn validate_tcp_options(tcp: &[u8], header_len: usize) -> Result<(), PacketError> {
    let options = &tcp[20..header_len];
    let mut pos = 0;
    while pos < options.len() {
        match options[pos] {
            0 => {
                // After EOL the bytes are padding, not a second option list.
                // Nonzero trailing bytes are ambiguous and fail closed.
                if options[pos + 1..].iter().any(|byte| *byte != 0) {
                    return Err(PacketError::Unsupported);
                }
                return Ok(());
            }
            1 => pos += 1, // NOP
            kind => {
                if pos + 2 > options.len() {
                    return Err(PacketError::Unsupported);
                }
                let len = usize::from(options[pos + 1]);
                if len < 2 || len > options.len() - pos {
                    return Err(PacketError::Unsupported);
                }
                // MSS, window scale, SACK-permitted, SACK blocks, timestamps.
                // TCP MD5 (19), TCP-AO (29), MPTCP (30), TFO (34) and
                // unknown/experimental kinds need dedicated semantics.
                let safe = match kind {
                    2 => len == 4,
                    3 => len == 3,
                    4 => len == 2,
                    5 => len >= 10 && (len - 2) % 8 == 0,
                    8 => len == 10,
                    _ => false,
                };
                if !safe {
                    return Err(PacketError::Unsupported);
                }
                pos += len;
            }
        }
    }
    Ok(())
}

fn parse(ip: &[u8]) -> Result<Parsed, PacketError> {
    let first = *ip.first().ok_or(PacketError::Truncated)?;
    let (family, tcp_start, source, destination) = match first >> 4 {
        4 => {
            if ip.len() < 20 {
                return Err(PacketError::Truncated);
            }
            let hlen = usize::from(first & 15) * 4;
            if hlen < 20 || hlen > ip.len() {
                return Err(PacketError::LengthMismatch);
            }
            // No IPv4 option parser/semantic verification exists yet. In
            // particular, LSRR/SSRR may alter forwarding after a tuple rewrite.
            // Reject ALL option-bearing packets until that is implemented.
            if hlen != 20 {
                return Err(PacketError::Unsupported);
            }
            let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            if total != ip.len() || total < hlen + 20 {
                return Err(PacketError::LengthMismatch);
            }
            // DF is permitted, reserved flag/MF/fragment-offset are not.
            if u16::from_be_bytes([ip[6], ip[7]]) & 0xbfff != 0 || ip[9] != 6 {
                return Err(PacketError::Unsupported);
            }
            if finish_checksum(word_sum(&ip[..hlen])) != 0 {
                return Err(PacketError::Checksum);
            }
            let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            (Family::V4, hlen, IpAddr::V4(src), IpAddr::V4(dst))
        }
        6 => {
            if ip.len() < 40 {
                return Err(PacketError::Truncated);
            }
            // IPv6 extension headers, fragments and jumbograms not yet supported.
            if ip[6] != 6 {
                return Err(PacketError::Unsupported);
            }
            let payload = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
            if payload < 20 || 40 + payload != ip.len() {
                return Err(PacketError::LengthMismatch);
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&ip[8..24]);
            dst.copy_from_slice(&ip[24..40]);
            (
                Family::V6,
                40,
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
            )
        }
        _ => return Err(PacketError::Unsupported),
    };
    let tcp = &ip[tcp_start..];
    if tcp.len() < 20 {
        return Err(PacketError::Truncated);
    }
    let hlen = usize::from(tcp[12] >> 4) * 4;
    if hlen < 20 || hlen > tcp.len() {
        return Err(PacketError::LengthMismatch);
    }
    validate_tcp_options(tcp, hlen)?;
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if src_port == 0 || dst_port == 0 {
        return Err(PacketError::InvalidPort);
    }
    if finish_checksum(pseudo_sum(ip, family, tcp.len()) + word_sum(tcp)) != 0 {
        return Err(PacketError::Checksum);
    }
    Ok(Parsed {
        packet: TcpPacket {
            tuple: TcpTuple {
                source: SocketAddr::new(source, src_port),
                destination: SocketAddr::new(destination, dst_port),
            },
            tcp_bytes: tcp.len(),
            data_bytes: tcp.len() - hlen,
        },
        family,
        tcp_start,
    })
}

/// Validate the full IPv4/IPv6 + TCP header and TCP checksum. This is not
/// proof of process ownership or driver packet capture.
pub fn inspect_tcp(ip: &[u8]) -> Result<TcpPacket, PacketError> {
    Ok(parse(ip)?.packet)
}

/// Mutate only after validation of checksums and exact original tuple.
/// This is a pure packet primitive, NOT an authorized route or active redirect.
/// Caller must separately prove the driver packet binding and routing policy.
pub fn rewrite_tcp_tuple(
    ip: &mut [u8],
    expected: TcpTuple,
    replacement: TcpTuple,
) -> Result<TcpPacket, PacketError> {
    let parsed = parse(ip)?;
    if parsed.packet.tuple != expected {
        return Err(PacketError::TupleMismatch);
    }
    if replacement.source.port() == 0 || replacement.destination.port() == 0 {
        return Err(PacketError::InvalidPort);
    }
    let same_family = match parsed.family {
        Family::V4 => replacement.source.is_ipv4() && replacement.destination.is_ipv4(),
        Family::V6 => replacement.source.is_ipv6() && replacement.destination.is_ipv6(),
    };
    if !same_family {
        return Err(PacketError::AddressFamilyMismatch);
    }
    match (replacement.source.ip(), replacement.destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            ip[12..16].copy_from_slice(&src.octets());
            ip[16..20].copy_from_slice(&dst.octets());
            ip[10..12].fill(0);
            let sum = finish_checksum(word_sum(&ip[..parsed.tcp_start]));
            ip[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ip[8..24].copy_from_slice(&src.octets());
            ip[24..40].copy_from_slice(&dst.octets());
        }
        _ => return Err(PacketError::AddressFamilyMismatch),
    }
    let t = parsed.tcp_start;
    ip[t..t + 2].copy_from_slice(&replacement.source.port().to_be_bytes());
    ip[t + 2..t + 4].copy_from_slice(&replacement.destination.port().to_be_bytes());
    ip[t + 16..t + 18].fill(0);
    let sum = finish_checksum(pseudo_sum(ip, parsed.family, ip.len() - t) + word_sum(&ip[t..]));
    ip[t + 16..t + 18].copy_from_slice(&sum.to_be_bytes());
    inspect_tcp(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(family: Family, data: &[u8]) -> Vec<u8> {
        let t = match family {
            Family::V4 => 20,
            Family::V6 => 40,
        };
        let mut ip = vec![0u8; t + 20 + data.len()];
        let len = ip.len();
        match family {
            Family::V4 => {
                ip[0] = 0x45;
                ip[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                ip[8] = 64;
                ip[9] = 6;
                ip[12..16].copy_from_slice(&[192, 0, 2, 11]);
                ip[16..20].copy_from_slice(&[198, 51, 100, 23]);
                let c = finish_checksum(word_sum(&ip[..20]));
                ip[10..12].copy_from_slice(&c.to_be_bytes());
            }
            Family::V6 => {
                ip[0] = 0x60;
                ip[4..6].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes());
                ip[6] = 6;
                ip[7] = 64;
                ip[8..24].copy_from_slice(&"2001:db8::11".parse::<Ipv6Addr>().unwrap().octets());
                ip[24..40].copy_from_slice(&"2001:db8::23".parse::<Ipv6Addr>().unwrap().octets());
            }
        }
        ip[t..t + 2].copy_from_slice(&54321u16.to_be_bytes());
        ip[t + 2..t + 4].copy_from_slice(&443u16.to_be_bytes());
        ip[t + 12] = 0x50;
        ip[t + 13] = 0x18;
        ip[t + 14..t + 16].copy_from_slice(&4096u16.to_be_bytes());
        ip[t + 20..].copy_from_slice(data);
        let c = finish_checksum(pseudo_sum(&ip, family, len - t) + word_sum(&ip[t..]));
        ip[t + 16..t + 18].copy_from_slice(&c.to_be_bytes());
        ip
    }

    #[test]
    fn ipv4_ipv6_rewrite_round_trip_with_odd_tcp_data() {
        for family in [Family::V4, Family::V6] {
            let original = packet(family, b"five!");
            let current = inspect_tcp(&original).unwrap();
            assert_eq!(current.data_bytes, 5);
            let mut changed = original.clone();
            let next = match family {
                Family::V4 => TcpTuple {
                    source: "127.0.0.1:40000".parse().unwrap(),
                    destination: "127.0.0.1:10080".parse().unwrap(),
                },
                Family::V6 => TcpTuple {
                    source: "[::1]:40000".parse().unwrap(),
                    destination: "[::1]:10080".parse().unwrap(),
                },
            };
            assert_eq!(
                rewrite_tcp_tuple(&mut changed, current.tuple, next)
                    .unwrap()
                    .tuple,
                next
            );
            rewrite_tcp_tuple(&mut changed, next, current.tuple).unwrap();
            assert_eq!(changed, original);
        }
    }

    fn with_tcp_options(mut ip: Vec<u8>, family: Family, options: &[u8]) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let tcp_start = match family {
            Family::V4 => 20,
            Family::V6 => 40,
        };
        ip.splice(tcp_start + 20..tcp_start + 20, options.iter().copied());
        let tcp_len = ip.len() - tcp_start;
        ip[tcp_start + 12] = ((5 + options.len() / 4) as u8) << 4;
        match family {
            Family::V4 => {
                let total = ip.len() as u16;
                ip[2..4].copy_from_slice(&total.to_be_bytes());
                ip[10..12].fill(0);
                let sum = finish_checksum(word_sum(&ip[..tcp_start]));
                ip[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            Family::V6 => {
                ip[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            }
        }
        ip[tcp_start + 16..tcp_start + 18].fill(0);
        let sum = finish_checksum(pseudo_sum(&ip, family, tcp_len) + word_sum(&ip[tcp_start..]));
        ip[tcp_start + 16..tcp_start + 18].copy_from_slice(&sum.to_be_bytes());
        ip
    }

    #[test]
    fn ordinary_tcp_options_survive_inverse_rewrite() {
        // MSS, NOP, window scale, SACK-permitted, timestamps, EOL/padding.
        let options = [
            2, 4, 5, 180, 1, 3, 3, 7, 4, 2, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0,
        ];
        for family in [Family::V4, Family::V6] {
            let original = with_tcp_options(packet(family, b"payload"), family, &options);
            let parsed = inspect_tcp(&original).unwrap();
            assert_eq!(parsed.data_bytes, 7);
            let replacement = match family {
                Family::V4 => TcpTuple {
                    source: "127.0.0.1:40000".parse().unwrap(),
                    destination: "127.0.0.1:10080".parse().unwrap(),
                },
                Family::V6 => TcpTuple {
                    source: "[::1]:40000".parse().unwrap(),
                    destination: "[::1]:10080".parse().unwrap(),
                },
            };
            let mut changed = original.clone();
            rewrite_tcp_tuple(&mut changed, parsed.tuple, replacement).unwrap();
            rewrite_tcp_tuple(&mut changed, replacement, parsed.tuple).unwrap();
            assert_eq!(changed, original);
        }
    }

    #[test]
    fn authenticated_multipath_unknown_and_malformed_tcp_options_fail_closed() {
        let mut md5 = vec![19, 18]; // TCP MD5 signature (RFC 2385)
        md5.extend_from_slice(&[0; 16]);
        md5.extend_from_slice(&[0, 0]);
        let cases = vec![
            md5,
            vec![29, 4, 1, 2],             // TCP-AO, address-authenticated
            vec![30, 4, 0x10, 0],          // MPTCP, path semantics
            vec![34, 4, 0, 1],             // TCP Fast Open, not handled
            vec![253, 4, 0, 0],           // experimental/unknown
            vec![8, 1, 0, 0],             // invalid option length
            vec![8, 10, 0, 0],            // truncated timestamp option
            vec![2, 3, 0, 0],             // malformed MSS
            vec![5, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // malformed SACK
            vec![0, 1, 1, 1],             // nonzero bytes after EOL
        ];
        for options in cases {
            for family in [Family::V4, Family::V6] {
                // Construct packets with valid IP/TCP checksums: rejection
                // must depend on option semantics, not incidental corruption.
                let mut packet_with_options =
                    with_tcp_options(packet(family, b"data"), family, &options);
                let original = packet_with_options.clone();
                let expected = inspect_tcp(&packet(family, b"data")).unwrap().tuple;
                assert_eq!(
                    inspect_tcp(&packet_with_options),
                    Err(PacketError::Unsupported)
                );
                assert_eq!(
                    rewrite_tcp_tuple(&mut packet_with_options, expected, expected),
                    Err(PacketError::Unsupported)
                );
                assert_eq!(packet_with_options, original);
            }
        }
    }

    #[test]
    fn checksum_and_length_corruption_rejected_without_mutation() {
        for family in [Family::V4, Family::V6] {
            let original = packet(family, b"payload");
            let tuple = inspect_tcp(&original).unwrap().tuple;
            let mut bad = original.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(inspect_tcp(&bad), Err(PacketError::Checksum));
            let before = bad.clone();
            assert_eq!(
                rewrite_tcp_tuple(&mut bad, tuple, tuple),
                Err(PacketError::Checksum)
            );
            assert_eq!(bad, before);
            let mut trailing = original.clone();
            trailing.push(0);
            assert_eq!(inspect_tcp(&trailing), Err(PacketError::LengthMismatch));
            let mut truncated = original.clone();
            truncated.truncate(10);
            assert_eq!(inspect_tcp(&truncated), Err(PacketError::Truncated));
        }
    }

    #[test]
    fn fragmentation_extension_headers_and_bad_flags_are_rejected() {
        let mut v4 = packet(Family::V4, b"");
        v4[6] |= 0x20;
        assert_eq!(inspect_tcp(&v4), Err(PacketError::Unsupported));
        let mut reserved = packet(Family::V4, b"");
        reserved[6] |= 0x80;
        assert_eq!(inspect_tcp(&reserved), Err(PacketError::Unsupported));
        let mut v6 = packet(Family::V6, b"");
        v6[6] = 44;
        assert_eq!(inspect_tcp(&v6), Err(PacketError::Unsupported));
    }

    #[test]
    fn valid_ipv4_options_are_not_rewritten_or_forwardable() {
        let tuple = inspect_tcp(&packet(Family::V4, b"hello")).unwrap().tuple;
        // NOP, valid loose and strict source routes with a single address.
        // Even innocuous options remain unsupported until header semantics
        // are implemented. LSRR=0x83, SSRR=0x89, len=7, pointer=4.
        let cases: &[&[u8]] = &[
            &[1, 1, 1, 1],
            &[0x83, 7, 4, 203, 0, 113, 9, 0],
            &[0x89, 7, 4, 203, 0, 113, 9, 0],
        ];
        for &options in cases {
            let mut ip = packet(Family::V4, b"hello");
            ip.splice(20..20, options.iter().copied());
            ip[0] = 0x40 | (5 + options.len() / 4) as u8;
            let total = ip.len() as u16;
            ip[2..4].copy_from_slice(&total.to_be_bytes());
            ip[10..12].fill(0);
            let header_len = 20 + options.len();
            let checksum = finish_checksum(word_sum(&ip[..header_len]));
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
            assert_eq!(finish_checksum(word_sum(&ip[..header_len])), 0);
            let original = ip.clone();
            assert_eq!(inspect_tcp(&ip), Err(PacketError::Unsupported));
            assert_eq!(
                rewrite_tcp_tuple(&mut ip, tuple, tuple),
                Err(PacketError::Unsupported)
            );
            assert_eq!(ip, original);
        }
    }

    #[test]
    fn mismatch_family_and_zero_ports_do_not_mutate() {
        let original = packet(Family::V4, b"data");
        let t = inspect_tcp(&original).unwrap().tuple;
        let target = TcpTuple {
            source: "127.0.0.1:40000".parse().unwrap(),
            destination: "127.0.0.1:10080".parse().unwrap(),
        };
        let mut ip = original.clone();
        assert_eq!(
            rewrite_tcp_tuple(&mut ip, target, t),
            Err(PacketError::TupleMismatch)
        );
        assert_eq!(ip, original);
        let invalid = TcpTuple {
            destination: "[::1]:10080".parse().unwrap(),
            ..target
        };
        assert_eq!(
            rewrite_tcp_tuple(&mut ip, t, invalid),
            Err(PacketError::AddressFamilyMismatch)
        );
        assert_eq!(ip, original);
        let zero = TcpTuple {
            destination: "127.0.0.1:0".parse().unwrap(),
            ..target
        };
        assert_eq!(
            rewrite_tcp_tuple(&mut ip, t, zero),
            Err(PacketError::InvalidPort)
        );
        assert_eq!(ip, original);
    }

    #[test]
    fn ipv4_header_and_tcp_mutations_are_detected() {
        let original = packet(Family::V4, b"even");
        let mut bad_header = original.clone();
        bad_header[8] ^= 1;
        assert_eq!(inspect_tcp(&bad_header), Err(PacketError::Checksum));
        let mut bad_tcp = original.clone();
        bad_tcp[34] ^= 1;
        assert_eq!(inspect_tcp(&bad_tcp), Err(PacketError::Checksum));
    }
}
