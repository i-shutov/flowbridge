//! Independently expressed native-x64 NDISRD wire contract. All multi-byte
//! fields are decoded from bytes: the vendor ABI uses pack(1), NOT Rust repr(C).
//! Contract: wiresock/ndisapi Common.h blob ba42da741693816d2d843f59b241aa827c1a3d3d.
//! No vendor implementation, driver, or ProxiFyre code is embedded here.

use std::collections::HashSet;

pub const ADAPTER_LIST_BYTES: usize = 8836;
pub const MAX_ADAPTERS: usize = 32;
pub const PACKET_HEADER_BYTES: usize = 52;
pub const MAX_FRAME_BYTES: usize = 9014;
pub const PACKET_BUFFER_BYTES: usize = PACKET_HEADER_BYTES + MAX_FRAME_BYTES;
pub const MODE_BYTES: usize = 12;
pub const REQUEST_BYTES: usize = 16;
pub const LISTEN_BOTH: u32 = 0x0c;
pub const TUNNEL_BOTH: u32 = 0x03;

pub const fn ioctl(index: u32) -> u32 {
    (0x8300 << 16) | ((0x830 + index) << 2)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Length,
    Count,
    Name,
    Handle,
    Direction,
}

/// Opaque handles are deliberately omitted from Debug and JSON diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct Adapter {
    pub handle: u64,
    pub name: String,
    pub medium: u32,
    pub mac: [u8; 6],
    pub mtu: u16,
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapter")
            .field("name", &self.name)
            .field("medium", &self.medium)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("validated wire bounds"))
}

pub fn decode_adapters(bytes: &[u8]) -> Result<Vec<Adapter>, WireError> {
    if bytes.len() != ADAPTER_LIST_BYTES {
        return Err(WireError::Length);
    }
    let count = u32le(bytes, 0) as usize;
    if count > MAX_ADAPTERS {
        return Err(WireError::Count);
    }
    let mut names = HashSet::new();
    let mut handles = HashSet::new();
    let mut adapters = Vec::with_capacity(count);
    for i in 0..count {
        let raw = &bytes[4 + i * 256..4 + (i + 1) * 256];
        let end = raw.iter().position(|b| *b == 0).ok_or(WireError::Name)?;
        if end == 0 || !raw[..end].iter().all(u8::is_ascii_graphic) {
            return Err(WireError::Name);
        }
        let name = std::str::from_utf8(&raw[..end])
            .map_err(|_| WireError::Name)?
            .to_owned();
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(WireError::Name);
        }
        let h = 8196 + i * 8; // 4 + 32 * 256, NO alignment padding
        let handle = u64::from_le_bytes(bytes[h..h + 8].try_into().map_err(|_| WireError::Length)?);
        if handle == 0 || !handles.insert(handle) {
            return Err(WireError::Handle);
        }
        let m = 8580 + i * 6;
        let mut mac = [0; 6];
        mac.copy_from_slice(&bytes[m..m + 6]);
        let mtu = 8772 + i * 2;
        adapters.push(Adapter {
            handle,
            name,
            medium: u32le(bytes, 8452 + i * 4),
            mac,
            mtu: u16::from_le_bytes([bytes[mtu], bytes[mtu + 1]]),
        });
    }
    Ok(adapters)
}

pub fn mode_request(adapter: u64, flags: u32) -> [u8; MODE_BYTES] {
    let mut out = [0; MODE_BYTES];
    out[..8].copy_from_slice(&adapter.to_le_bytes());
    out[8..].copy_from_slice(&flags.to_le_bytes());
    out
}

pub fn packet_request(adapter: u64, buffer_address: u64) -> [u8; REQUEST_BYTES] {
    let mut out = [0; REQUEST_BYTES];
    out[..8].copy_from_slice(&adapter.to_le_bytes());
    out[8..].copy_from_slice(&buffer_address.to_le_bytes());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToAdapter,
    ToStack,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PacketView<'a> {
    pub direction: Direction,
    pub ndis_flags: u32,
    pub vlan_metadata: u32,
    pub filter_id: u32,
    pub frame: &'a [u8],
}

pub fn decode_packet(bytes: &[u8]) -> Result<PacketView<'_>, WireError> {
    if bytes.len() != PACKET_BUFFER_BYTES {
        return Err(WireError::Length);
    }
    let length = u32le(bytes, 20) as usize;
    if !(14..=MAX_FRAME_BYTES).contains(&length) {
        return Err(WireError::Length);
    }
    let direction = match u32le(bytes, 16) {
        1 => Direction::ToAdapter,
        2 => Direction::ToStack,
        _ => return Err(WireError::Direction),
    };
    Ok(PacketView {
        direction,
        ndis_flags: u32le(bytes, 24),
        vlan_metadata: u32le(bytes, 28),
        filter_id: u32le(bytes, 32),
        frame: &bytes[PACKET_HEADER_BYTES..PACKET_HEADER_BYTES + length],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_fixture() -> Vec<u8> {
        // Independent byte positions transcribed from the PACKED x64 contract.
        // Do not call the production encoder or derive offsets from repr(C).
        let mut raw = vec![0; 8836];
        raw[..4].copy_from_slice(&1u32.to_le_bytes());
        raw[4..14].copy_from_slice(b"adapter-A\0");
        raw[8196..8204].copy_from_slice(&0x1020304050607080u64.to_le_bytes());
        raw[8452..8456].copy_from_slice(&17u32.to_le_bytes());
        raw[8580..8586].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        raw[8772..8774].copy_from_slice(&1500u16.to_le_bytes());
        raw
    }

    #[test]
    fn packed_golden_adapter_does_not_use_host_alignment() {
        let a = decode_adapters(&fixed_fixture()).unwrap();
        assert_eq!(a[0].handle, 0x1020304050607080);
        assert_eq!(a[0].name, "adapter-A");
        assert_eq!(a[0].medium, 17);
        assert_eq!(a[0].mac, [2, 3, 4, 5, 6, 7]);
        assert_eq!(a[0].mtu, 1500);
        assert!(!format!("{:?}", a[0]).contains("1020304050607080"));
        assert_eq!(decode_adapters(&vec![0; 8840]), Err(WireError::Length));
        assert_eq!(
            mode_request(0x1122334455667788, 12),
            [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 12, 0, 0, 0]
        );
    }

    #[test]
    fn malformed_inventory_is_not_partial_success() {
        let mut a = fixed_fixture();
        a[0] = 33;
        assert_eq!(decode_adapters(&a), Err(WireError::Count));
        a = fixed_fixture();
        a[4] = 0;
        assert_eq!(decode_adapters(&a), Err(WireError::Name));
        a = fixed_fixture();
        a[8196..8204].fill(0);
        assert_eq!(decode_adapters(&a), Err(WireError::Handle));
        a = fixed_fixture();
        a[0] = 2;
        a[260..270].copy_from_slice(b"adapter-B\0");
        a[8204..8212].copy_from_slice(&0x1020304050607080u64.to_le_bytes());
        assert_eq!(decode_adapters(&a), Err(WireError::Handle));
    }

    #[test]
    fn packet_bytes_are_bounded_and_direction_is_not_guessed() {
        let mut b = vec![0; 9066];
        b[16] = 1;
        b[20] = 14;
        b[52..66].fill(7);
        let packet = decode_packet(&b).unwrap();
        assert_eq!(packet.frame, &[7; 14]);
        assert_eq!(packet.direction, Direction::ToAdapter);
        b[16] = 3;
        assert_eq!(decode_packet(&b), Err(WireError::Direction));
        b[16] = 2;
        b[20..24].copy_from_slice(&9015u32.to_le_bytes());
        assert_eq!(decode_packet(&b), Err(WireError::Length));
        assert_eq!(decode_packet(&b[..52]), Err(WireError::Length));
        assert_eq!(ioctl(1), 0x830020c4);
        assert_eq!(ioctl(4), 0x830020d0);
        assert_eq!(ioctl(13), 0x830020f4);
    }
}
