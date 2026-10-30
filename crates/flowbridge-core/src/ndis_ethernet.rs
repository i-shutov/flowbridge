//! Conservative link-layer boundary for future native NDISRD Ethernet buffers.
//!
//! This is an OFFLINE decoder: it neither opens the driver nor authorizes
//! forwarding. NDISRD returns a link-layer frame, while tcp_packet operates on
//! bare IPv4/IPv6. Do not strip 14 bytes unconditionally: VLAN tags, padding,
//! offloads, non-Ethernet media, adapter identity and direction must be handled.
//! Unsupported frames require a BLOCK verdict in any future protected worker.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    Oversize,
    Unsupported,
    LengthMismatch,
    NonZeroPadding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRegion {
    /// Offset of the first IP header byte within the input Ethernet frame.
    pub offset: usize,
    /// Exact IP datagram length (excludes Ethernet padding).
    pub length: usize,
    pub padding: usize,
    pub vlan_tags: u8,
    pub version: IpVersion,
}

// A conservative offline ceiling, not a driver MTU or adapter capability
// assertion. Actual limits must be obtained from validated NDISRD adapter I/O.
const MAX_ETHERNET_BYTES: usize = 9216;
const ETHERNET_HEADER_BYTES: usize = 14;
const MIN_ETHERNET_PAYLOAD: usize = 46;
const IPV4_ETHERTYPE: u16 = 0x0800;
const IPV6_ETHERTYPE: u16 = 0x86dd;
const DOT1Q_ETHERTYPE: u16 = 0x8100;
const DOT1AD_ETHERTYPE: u16 = 0x88a8;

fn u16be(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

/// Identify precisely the IPv4/IPv6 bytes in an Ethernet frame.
///
/// Supports at most two 802.1Q/802.1ad VLAN tags. Ethernet FCS and nonzero
/// padding are not supported. This does not verify Ethernet source/destination,
/// adapter membership, IP checksums, TCP checksums or process ownership.
/// Those are independent mandatory admission checks before packet reinjection.
pub fn inspect_l2_ip(frame: &[u8]) -> Result<IpRegion, FrameError> {
    if frame.len() > MAX_ETHERNET_BYTES {
        return Err(FrameError::Oversize);
    }
    if frame.len() < ETHERNET_HEADER_BYTES {
        return Err(FrameError::Truncated);
    }
    let mut offset = ETHERNET_HEADER_BYTES;
    let mut ethertype = u16be(frame, 12);
    let mut vlan_tags = 0u8;
    while ethertype == DOT1Q_ETHERTYPE || ethertype == DOT1AD_ETHERTYPE {
        if vlan_tags == 2 {
            return Err(FrameError::Unsupported);
        }
        if frame.len() < offset + 4 {
            return Err(FrameError::Truncated);
        }
        let tci = u16be(frame, offset);
        // VLAN ID 4095 is reserved; VLAN 0 (priority-tagged) is legitimate.
        if tci & 0x0fff == 0x0fff {
            return Err(FrameError::Unsupported);
        }
        ethertype = u16be(frame, offset + 2);
        offset += 4;
        vlan_tags += 1;
    }
    let version = match ethertype {
        IPV4_ETHERTYPE => IpVersion::V4,
        IPV6_ETHERTYPE => IpVersion::V6,
        _ => return Err(FrameError::Unsupported),
    };
    let remaining = frame.len() - offset;
    let length = match version {
        IpVersion::V4 => {
            if remaining < 20 {
                return Err(FrameError::Truncated);
            }
            if frame[offset] >> 4 != 4 {
                return Err(FrameError::Unsupported);
            }
            let ihl = usize::from(frame[offset] & 0x0f) * 4;
            let total = usize::from(u16be(frame, offset + 2));
            if ihl < 20 || total < ihl {
                return Err(FrameError::LengthMismatch);
            }
            total
        }
        IpVersion::V6 => {
            if remaining < 40 {
                return Err(FrameError::Truncated);
            }
            if frame[offset] >> 4 != 6 {
                return Err(FrameError::Unsupported);
            }
            let payload = usize::from(u16be(frame, offset + 4));
            // IPv6 jumbograms require hop-by-hop semantics not implemented.
            if payload == 0 {
                return Err(FrameError::Unsupported);
            }
            40 + payload
        }
    };
    if length > remaining {
        return Err(FrameError::LengthMismatch);
    }
    let padding = remaining - length;
    // Only minimum-size Ethernet zero padding is admitted. Do not treat an
    // arbitrary trailer, FCS or stale driver-buffer bytes as IPv4/IPv6 data.
    if padding > MIN_ETHERNET_PAYLOAD.saturating_sub(length) {
        return Err(FrameError::LengthMismatch);
    }
    if frame[offset + length..].iter().any(|b| *b != 0) {
        return Err(FrameError::NonZeroPadding);
    }
    Ok(IpRegion {
        offset,
        length,
        padding,
        vlan_tags,
        version,
    })
}

/// Return only the complete IP datagram, excluding L2 and zero padding.
/// The borrowed region can be passed to tcp_packet::rewrite_tcp_tuple, but
/// successful offline parsing/rewrite never authorizes driver reinjection.
pub fn ip_packet_mut(frame: &mut [u8]) -> Result<(&mut [u8], IpRegion), FrameError> {
    let info = inspect_l2_ip(frame)?;
    Ok((&mut frame[info.offset..info.offset + info.length], info))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(version: IpVersion, tags: u8, pad: usize) -> Vec<u8> {
        let mut frame = vec![0u8; ETHERNET_HEADER_BYTES];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        let ether = match version {
            IpVersion::V4 => IPV4_ETHERTYPE,
            IpVersion::V6 => IPV6_ETHERTYPE,
        };
        if tags == 0 {
            frame[12..14].copy_from_slice(&ether.to_be_bytes());
        } else {
            frame[12..14].copy_from_slice(&DOT1AD_ETHERTYPE.to_be_bytes());
            frame.extend_from_slice(&[0x00, 0x64]);
            if tags == 1 {
                frame.extend_from_slice(&ether.to_be_bytes());
            } else {
                frame.extend_from_slice(&DOT1Q_ETHERTYPE.to_be_bytes());
                frame.extend_from_slice(&[0x00, 0xc8]);
                frame.extend_from_slice(&ether.to_be_bytes());
            }
        }
        match version {
            IpVersion::V4 => {
                let mut ip = vec![0u8; 40];
                ip[0] = 0x45;
                ip[2..4].copy_from_slice(&40u16.to_be_bytes());
                ip[9] = 6;
                frame.extend(ip);
            }
            IpVersion::V6 => {
                let mut ip = vec![0u8; 60];
                ip[0] = 0x60;
                ip[4..6].copy_from_slice(&20u16.to_be_bytes());
                ip[6] = 6;
                frame.extend(ip);
            }
        }
        frame.extend(std::iter::repeat_n(0, pad));
        frame
    }

    #[test]
    fn ipv4_ipv6_and_qinq_have_exact_payload_offsets() {
        for version in [IpVersion::V4, IpVersion::V6] {
            for tags in 0..=2 {
                let pad = if version == IpVersion::V4 { 6 } else { 0 };
                let frame = fixture(version, tags, pad);
                let region = inspect_l2_ip(&frame).unwrap();
                assert_eq!(region.offset, 14 + 4 * usize::from(tags));
                assert_eq!(region.vlan_tags, tags);
                assert_eq!(region.version, version);
                assert_eq!(region.padding, pad);
                assert_eq!(
                    region.length,
                    if version == IpVersion::V4 { 40 } else { 60 }
                );
            }
        }
    }

    #[test]
    fn mutable_ip_slice_excludes_link_layer_and_padding() {
        let mut frame = fixture(IpVersion::V4, 2, 6);
        let original = frame.clone();
        let (ip, region) = ip_packet_mut(&mut frame).unwrap();
        assert_eq!(ip.len(), 40);
        assert_eq!(region.offset, 22);
        ip[8] = 31;
        assert_eq!(&frame[..22], &original[..22]);
        assert_eq!(&frame[62..], &original[62..]);
        assert_eq!(frame[30], 31);
    }

    #[test]
    fn trailers_nonzero_padding_and_inconsistent_lengths_are_rejected() {
        let mut nonzero = fixture(IpVersion::V4, 0, 6);
        *nonzero.last_mut().unwrap() = 1;
        assert_eq!(inspect_l2_ip(&nonzero), Err(FrameError::NonZeroPadding));
        let mut extra = fixture(IpVersion::V4, 0, 7);
        assert_eq!(inspect_l2_ip(&extra), Err(FrameError::LengthMismatch));
        extra.truncate(14 + 35);
        assert_eq!(inspect_l2_ip(&extra), Err(FrameError::LengthMismatch));
        let mut v6 = fixture(IpVersion::V6, 0, 0);
        v6[18] = 0;
        v6[19] = 0;
        assert_eq!(inspect_l2_ip(&v6), Err(FrameError::Unsupported));
    }

    #[test]
    fn vlan_truncation_unknown_media_and_oversize_fail_closed() {
        assert_eq!(inspect_l2_ip(&[0; 13]), Err(FrameError::Truncated));
        let vlan_incomplete = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0x00, 0x00];
        assert_eq!(inspect_l2_ip(&vlan_incomplete), Err(FrameError::Truncated));
        let mut arp = fixture(IpVersion::V4, 0, 0);
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert_eq!(inspect_l2_ip(&arp), Err(FrameError::Unsupported));
        let mut reserved_vid = fixture(IpVersion::V4, 1, 0);
        reserved_vid[14..16].copy_from_slice(&0x0fffu16.to_be_bytes());
        assert_eq!(inspect_l2_ip(&reserved_vid), Err(FrameError::Unsupported));
        let mut triple = fixture(IpVersion::V4, 2, 0);
        triple[20..22].copy_from_slice(&DOT1Q_ETHERTYPE.to_be_bytes());
        assert_eq!(inspect_l2_ip(&triple), Err(FrameError::Unsupported));
        let large = vec![0u8; MAX_ETHERNET_BYTES + 1];
        assert_eq!(inspect_l2_ip(&large), Err(FrameError::Oversize));
    }

    #[test]
    fn wrong_ip_version_and_ipv4_ihl_do_not_pass() {
        let mut wrong = fixture(IpVersion::V4, 0, 0);
        wrong[14] = 0x60;
        assert_eq!(inspect_l2_ip(&wrong), Err(FrameError::Unsupported));
        let mut invalid = fixture(IpVersion::V4, 0, 0);
        invalid[14] = 0x44;
        assert_eq!(inspect_l2_ip(&invalid), Err(FrameError::LengthMismatch));
        let mut short_v6 = fixture(IpVersion::V6, 0, 0);
        short_v6.truncate(14 + 39);
        assert_eq!(inspect_l2_ip(&short_v6), Err(FrameError::Truncated));
    }
}
