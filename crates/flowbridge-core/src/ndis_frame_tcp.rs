//! Offline, transactional Ethernet/VLAN-to-TCP tuple rewrite boundary.
//!
//! This module never opens NDISRD, captures packets, authorizes owners,
//! chooses routes or injects traffic. A future protected-mode worker must
//! independently authorize adapter, direction, process and flow state.
//! Unsupported packets produce an error, NEVER a DIRECT fallback.
//!
//! The scratch slice is caller-owned, allowing reuse by a bounded worker.
//! On any error the original Ethernet frame is byte-for-byte unchanged.

use crate::ndis_ethernet::{inspect_l2_ip, FrameError, IpRegion};
use crate::tcp_packet::{inspect_tcp, rewrite_tcp_tuple, PacketError, TcpPacket, TcpTuple};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameTcpError {
    Frame(FrameError),
    Packet(PacketError),
    ScratchTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTcpPacket {
    pub region: IpRegion,
    pub tcp: TcpPacket,
}

/// Inspect TCP inside a *complete* Ethernet-II frame (0..=2 VLAN tags).
/// Does not claim packet provenance, ownership, intercept or redirect.
pub fn inspect_ethernet_tcp(frame: &[u8]) -> Result<FrameTcpPacket, FrameTcpError> {
    let region = inspect_l2_ip(frame).map_err(FrameTcpError::Frame)?;
    let ip = &frame[region.offset..region.offset + region.length];
    let tcp = inspect_tcp(ip).map_err(FrameTcpError::Packet)?;
    Ok(FrameTcpPacket { region, tcp })
}

/// Transactionally rewrite ONLY the datagram bytes inside a verified L2 frame.
///
/// The caller must supply a scratch buffer at least as large as the IP region.
/// Parsing, tuple matching, checksums and all candidate rewriting occur in
/// scratch. The frame is updated only after the complete candidate succeeds.
/// Thus a rejection cannot leave a partially modified packet in an I/O queue.
/// No frame reinjection or protected-routing authorization is performed.
pub fn rewrite_ethernet_tcp_tuple(
    frame: &mut [u8],
    scratch: &mut [u8],
    expected: TcpTuple,
    replacement: TcpTuple,
) -> Result<FrameTcpPacket, FrameTcpError> {
    let region = inspect_l2_ip(frame).map_err(FrameTcpError::Frame)?;
    if scratch.len() < region.length {
        return Err(FrameTcpError::ScratchTooSmall);
    }
    let ip = &mut scratch[..region.length];
    ip.copy_from_slice(&frame[region.offset..region.offset + region.length]);
    let tcp = rewrite_tcp_tuple(ip, expected, replacement).map_err(FrameTcpError::Packet)?;
    frame[region.offset..region.offset + region.length].copy_from_slice(ip);
    Ok(FrameTcpPacket { region, tcp })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndis_ethernet::IpVersion;
    use std::net::{Ipv6Addr, SocketAddr};

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            sum += u32::from(pair[0]) << 8;
            sum += u32::from(*pair.get(1).unwrap_or(&0));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn original_packet(version: IpVersion) -> Vec<u8> {
        let tcp_offset = if version == IpVersion::V4 { 20 } else { 40 };
        let mut ip = vec![0u8; tcp_offset + 20];
        if version == IpVersion::V4 {
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&40u16.to_be_bytes());
            ip[8] = 64;
            ip[9] = 6;
            ip[12..16].copy_from_slice(&[192, 0, 2, 10]);
            ip[16..20].copy_from_slice(&[198, 51, 100, 20]);
            let sum = checksum(&ip[..20]);
            ip[10..12].copy_from_slice(&sum.to_be_bytes());
        } else {
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&20u16.to_be_bytes());
            ip[6] = 6;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
            ip[24..40].copy_from_slice(&"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
        }
        ip[tcp_offset..tcp_offset + 2].copy_from_slice(&54321u16.to_be_bytes());
        ip[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&443u16.to_be_bytes());
        ip[tcp_offset + 12] = 0x50;
        ip[tcp_offset + 13] = 0x10; // ACK
        ip[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&4096u16.to_be_bytes());

        let mut pseudo = Vec::new();
        if version == IpVersion::V4 {
            pseudo.extend_from_slice(&ip[12..20]);
            pseudo.extend_from_slice(&[0, 6, 0, 20]);
        } else {
            pseudo.extend_from_slice(&ip[8..40]);
            pseudo.extend_from_slice(&20u32.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
        }
        pseudo.extend_from_slice(&ip[tcp_offset..]);
        let sum = checksum(&pseudo);
        ip[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&sum.to_be_bytes());
        assert!(inspect_tcp(&ip).is_ok());
        ip
    }

    fn frame(version: IpVersion, tags: u8) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        let ether = if version == IpVersion::V4 {
            0x0800u16
        } else {
            0x86ddu16
        };
        if tags == 0 {
            frame[12..14].copy_from_slice(&ether.to_be_bytes());
        } else {
            frame[12..14].copy_from_slice(&0x88a8u16.to_be_bytes());
            frame.extend_from_slice(&[0x00, 0x64]);
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&[0x00, 0xc8]);
            frame.extend_from_slice(&ether.to_be_bytes());
        }
        frame.extend_from_slice(&original_packet(version));
        if version == IpVersion::V4 {
            frame.extend_from_slice(&[0; 6]); // Ethernet minimum payload, not IP bytes
        }
        frame
    }

    // Build a complete Ethernet frame with a correctly checksummed TCP option
    // header; unsupported-option tests must fail for semantics, not bad bytes.
    fn frame_with_tcp_options(version: IpVersion, tags: u8, options: &[u8]) -> Vec<u8> {
        assert!(!options.is_empty() && options.chunks_exact(4).remainder().is_empty());
        let mut wire = frame(version, tags);
        let region = inspect_l2_ip(&wire).unwrap();
        wire.truncate(region.offset + region.length);
        let ip_start = region.offset;
        let tcp_start = ip_start + if version == IpVersion::V4 { 20 } else { 40 };
        wire.splice(tcp_start + 20..tcp_start + 20, options.iter().copied());
        let tcp_length = 20 + options.len();
        let ip_length = region.length + options.len();
        wire[tcp_start + 12] = ((tcp_length / 4) as u8) << 4;

        let mut pseudo = Vec::new();
        if version == IpVersion::V4 {
            wire[ip_start + 2..ip_start + 4].copy_from_slice(&(ip_length as u16).to_be_bytes());
            wire[ip_start + 10..ip_start + 12].fill(0);
            let ip_checksum = checksum(&wire[ip_start..ip_start + 20]);
            wire[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());
            assert_eq!(checksum(&wire[ip_start..ip_start + 20]), 0);
            pseudo.extend_from_slice(&wire[ip_start + 12..ip_start + 20]);
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&(tcp_length as u16).to_be_bytes());
        } else {
            wire[ip_start + 4..ip_start + 6].copy_from_slice(&(tcp_length as u16).to_be_bytes());
            pseudo.extend_from_slice(&wire[ip_start + 8..ip_start + 40]);
            pseudo.extend_from_slice(&(tcp_length as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
        }
        wire[tcp_start + 16..tcp_start + 18].fill(0);
        pseudo.extend_from_slice(&wire[tcp_start..]);
        let tcp_checksum = checksum(&pseudo);
        wire[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        let checksum_start = pseudo.len() - tcp_length + 16;
        pseudo[checksum_start..checksum_start + 2].copy_from_slice(&tcp_checksum.to_be_bytes());
        assert_eq!(checksum(&pseudo), 0);
        wire.extend(std::iter::repeat_n(0, 46usize.saturating_sub(ip_length)));
        assert_eq!(inspect_l2_ip(&wire).unwrap().length, ip_length);
        wire
    }

    fn replacement(version: IpVersion) -> TcpTuple {
        match version {
            IpVersion::V4 => TcpTuple {
                source: "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
                destination: "127.0.0.1:10080".parse::<SocketAddr>().unwrap(),
            },
            IpVersion::V6 => TcpTuple {
                source: "[::1]:40000".parse::<SocketAddr>().unwrap(),
                destination: "[::1]:10080".parse::<SocketAddr>().unwrap(),
            },
        }
    }

    #[test]
    fn ipv4_ipv6_qinq_rewrite_is_reversible_and_preserves_l2_padding() {
        for version in [IpVersion::V4, IpVersion::V6] {
            for tags in [0, 2] {
                let mut original = frame(version, tags);
                let before = original.clone();
                let info = inspect_ethernet_tcp(&original).unwrap();
                let mut scratch = vec![0xa5u8; 128];
                let next = replacement(version);
                let changed =
                    rewrite_ethernet_tcp_tuple(&mut original, &mut scratch, info.tcp.tuple, next)
                        .unwrap();
                assert_eq!(changed.tcp.tuple, next);
                let end = info.region.offset + info.region.length;
                assert_eq!(
                    &original[..info.region.offset],
                    &before[..info.region.offset]
                );
                assert_eq!(&original[end..], &before[end..]);
                assert_eq!(inspect_ethernet_tcp(&original).unwrap().tcp.tuple, next);
                rewrite_ethernet_tcp_tuple(&mut original, &mut scratch, next, info.tcp.tuple)
                    .unwrap();
                assert_eq!(original, before);
            }
        }
    }

    #[test]
    fn insufficient_scratch_and_tuple_mismatch_never_mutate_frame() {
        let mut frame = frame(IpVersion::V4, 2);
        let before = frame.clone();
        let tuple = inspect_ethernet_tcp(&frame).unwrap().tcp.tuple;
        let replacement = replacement(IpVersion::V4);
        let mut tiny = [0u8; 39];
        assert_eq!(
            rewrite_ethernet_tcp_tuple(&mut frame, &mut tiny, tuple, replacement),
            Err(FrameTcpError::ScratchTooSmall)
        );
        let mut scratch = [0u8; 128];
        assert_eq!(
            rewrite_ethernet_tcp_tuple(&mut frame, &mut scratch, replacement, tuple),
            Err(FrameTcpError::Packet(PacketError::TupleMismatch))
        );
        assert_eq!(frame, before);
    }

    #[test]
    fn corrupt_tcp_checksum_and_nonzero_padding_are_immutable_rejections() {
        for version in [IpVersion::V4, IpVersion::V6] {
            let mut corrupt = frame(version, 0);
            let info = inspect_ethernet_tcp(&corrupt).unwrap();
            // Flip TCP ACK window (outside the IP and TCP checksum fields).
            corrupt[info.region.offset + info.region.length - 6] ^= 1;
            let before = corrupt.clone();
            let mut scratch = [0u8; 128];
            assert_eq!(
                rewrite_ethernet_tcp_tuple(
                    &mut corrupt,
                    &mut scratch,
                    info.tcp.tuple,
                    replacement(version)
                ),
                Err(FrameTcpError::Packet(PacketError::Checksum))
            );
            assert_eq!(corrupt, before);
        }
        let mut padded = frame(IpVersion::V4, 0);
        *padded.last_mut().unwrap() = 0x55;
        let before = padded.clone();
        let tuple = inspect_ethernet_tcp(&frame(IpVersion::V4, 0))
            .unwrap()
            .tcp
            .tuple;
        let mut scratch = [0u8; 128];
        assert_eq!(
            rewrite_ethernet_tcp_tuple(
                &mut padded,
                &mut scratch,
                tuple,
                replacement(IpVersion::V4)
            ),
            Err(FrameTcpError::Frame(FrameError::NonZeroPadding))
        );
        assert_eq!(padded, before);
    }

    #[test]
    fn safe_tcp_options_preserve_ethernet_and_qinq_in_both_directions() {
        // MSS, NOP, window scale, SACK permitted and EOL-free padding.
        let options = [2, 4, 5, 180, 1, 3, 3, 7, 4, 2, 1, 1];
        for version in [IpVersion::V4, IpVersion::V6] {
            for tags in [0, 2] {
                let mut wire = frame_with_tcp_options(version, tags, &options);
                let original = wire.clone();
                let prior = inspect_ethernet_tcp(&wire).unwrap();
                let next = replacement(version);
                let mut scratch = [0u8; 256];
                rewrite_ethernet_tcp_tuple(&mut wire, &mut scratch, prior.tcp.tuple, next).unwrap();
                assert_eq!(inspect_ethernet_tcp(&wire).unwrap().tcp.tuple, next);
                rewrite_ethernet_tcp_tuple(&mut wire, &mut scratch, next, prior.tcp.tuple).unwrap();
                assert_eq!(wire, original);
            }
        }
    }

    #[test]
    fn prohibited_tcp_options_are_rejected_before_any_ethernet_mutation() {
        let mut md5 = vec![19, 18];
        md5.extend_from_slice(&[0; 16]);
        md5.extend_from_slice(&[0, 0]);
        let cases = [
            md5,                  // TCP-MD5
            vec![29, 4, 1, 2],    // TCP-AO
            vec![30, 4, 0x10, 0], // MPTCP
            vec![34, 4, 0, 1],    // TCP Fast Open
            vec![253, 4, 0, 0],   // experimental
            vec![8, 1, 0, 0],     // invalid option length
            vec![0, 1, 1, 1],     // nonzero padding after EOL
        ];
        for options in cases {
            for version in [IpVersion::V4, IpVersion::V6] {
                for tags in [0, 2] {
                    let mut wire = frame_with_tcp_options(version, tags, &options);
                    let original = wire.clone();
                    let expected = inspect_ethernet_tcp(&frame(version, tags))
                        .unwrap()
                        .tcp
                        .tuple;
                    let mut scratch = [0u8; 256];
                    assert_eq!(
                        inspect_ethernet_tcp(&wire),
                        Err(FrameTcpError::Packet(PacketError::Unsupported))
                    );
                    assert_eq!(
                        rewrite_ethernet_tcp_tuple(
                            &mut wire,
                            &mut scratch,
                            expected,
                            replacement(version)
                        ),
                        Err(FrameTcpError::Packet(PacketError::Unsupported))
                    );
                    assert_eq!(wire, original);
                }
            }
        }
    }

    #[test]
    fn unsupported_media_and_ipv6_extensions_fail_before_commit() {
        let mut unknown = frame(IpVersion::V4, 0);
        unknown[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let before = unknown.clone();
        let tuple = inspect_ethernet_tcp(&frame(IpVersion::V4, 0))
            .unwrap()
            .tcp
            .tuple;
        let mut scratch = [0u8; 128];
        assert_eq!(
            rewrite_ethernet_tcp_tuple(
                &mut unknown,
                &mut scratch,
                tuple,
                replacement(IpVersion::V4)
            ),
            Err(FrameTcpError::Frame(FrameError::Unsupported))
        );
        assert_eq!(unknown, before);

        let mut extensions = frame(IpVersion::V6, 2);
        let ip_offset = 22;
        extensions[ip_offset + 6] = 44; // IPv6 fragment header
        let before = extensions.clone();
        let tuple = inspect_ethernet_tcp(&frame(IpVersion::V6, 2))
            .unwrap()
            .tcp
            .tuple;
        assert_eq!(
            rewrite_ethernet_tcp_tuple(
                &mut extensions,
                &mut scratch,
                tuple,
                replacement(IpVersion::V6)
            ),
            Err(FrameTcpError::Packet(PacketError::Unsupported))
        );
        assert_eq!(extensions, before);
    }
}
