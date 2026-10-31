//! Windows IPv4/IPv6 UDP *local bind owner candidate*, never a packet owner.
//! GetExtendedUdpTable has no remote address or traffic/packet evidence. Two
//! local-table snapshots and a pinned PID+creation epoch cannot prove a
//! captured UDP datagram belongs to this process or authorize a route.
//! All externally emitted diagnostics redact process identity and endpoints.
#![cfg(windows)]

use crate::windows_tcp_owner::{OwnedProcess, ProcessEvidence};
use serde_json::{json, Value};
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::ptr::{null_mut, read_unaligned};
use std::time::Duration;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TABLE_ROWS: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UdpOwnerRow {
    local: SocketAddr,
    pid: u32,
}

fn port(network_order_low_word: u32) -> u16 {
    u16::from_be(network_order_low_word as u16)
}

fn ipv4_row(row: MIB_UDPROW_OWNER_PID) -> UdpOwnerRow {
    UdpOwnerRow {
        local: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            port(row.dwLocalPort),
        ),
        pid: row.dwOwningPid,
    }
}

fn ipv6_row(row: MIB_UDP6ROW_OWNER_PID) -> UdpOwnerRow {
    UdpOwnerRow {
        local: SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(row.ucLocalAddr),
            port(row.dwLocalPort),
            0,
            u32::from_be(row.dwLocalScopeId),
        )),
        pid: row.dwOwningPid,
    }
}

fn read_table(af: u32) -> Result<(Vec<u32>, usize), String> {
    let mut needed = 0u32;
    // SAFETY: Null output requests only the buffer size.
    let first = unsafe {
        GetExtendedUdpTable(null_mut(), &mut needed, 0, af, UDP_TABLE_OWNER_PID, 0)
    };
    if first != ERROR_INSUFFICIENT_BUFFER || needed < 4 {
        return Err(format!("UDP IP Helper sizing failed: {first}"));
    }
    for _ in 0..4 {
        if needed as usize > MAX_TABLE_BYTES {
            return Err("UDP IP Helper table exceeds bounded buffer".into());
        }
        let word_count = (needed as usize).div_ceil(size_of::<u32>());
        let mut words = vec![0u32; word_count];
        let mut capacity = (words.len() * size_of::<u32>()) as u32;
        // SAFETY: Aligned owned buffer, synchronous API, no retained pointers.
        let status = unsafe {
            GetExtendedUdpTable(
                words.as_mut_ptr().cast::<c_void>(),
                &mut capacity,
                0,
                af,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if status == 0 {
            if capacity as usize > words.len() * size_of::<u32>() {
                return Err("UDP IP Helper oversized success".into());
            }
            return Ok((words, capacity as usize));
        }
        if status != ERROR_INSUFFICIENT_BUFFER || capacity <= needed {
            return Err(format!("UDP IP Helper query failed: {status}"));
        }
        needed = capacity;
    }
    Err("UDP IP Helper table changed too often".into())
}

fn decode_rows<R: Copy>(
    words: &[u32],
    used_bytes: usize,
    offset: usize,
    convert: impl Fn(R) -> UdpOwnerRow,
) -> Result<Vec<UdpOwnerRow>, String> {
    if words.is_empty() || used_bytes < offset {
        return Err("UDP IP Helper table header truncated".into());
    }
    let count = words[0] as usize;
    let row_bytes = size_of::<R>();
    if row_bytes == 0
        || count > MAX_TABLE_ROWS
        || count
            .checked_mul(row_bytes)
            .and_then(|bytes| bytes.checked_add(offset))
            .is_none_or(|end| end > used_bytes)
    {
        return Err("UDP IP Helper row count exceeds bounded buffer".into());
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let at = offset + index * row_bytes;
        // SAFETY: Checked the complete count*size+offset; row may be unaligned.
        let row = unsafe {
            read_unaligned(words.as_ptr().cast::<u8>().add(at).cast::<R>())
        };
        rows.push(convert(row));
    }
    Ok(rows)
}

fn snapshot(local: SocketAddr) -> Result<Vec<UdpOwnerRow>, String> {
    let af = if local.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    } as u32;
    let (bytes, used) = read_table(af)?;
    if local.is_ipv4() {
        decode_rows(
            &bytes,
            used,
            offset_of!(MIB_UDPTABLE_OWNER_PID, table),
            ipv4_row,
        )
    } else {
        decode_rows(
            &bytes,
            used,
            offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
            ipv6_row,
        )
    }
}

fn validate_local(local: SocketAddr) -> Result<(), String> {
    if local.port() == 0 || local.ip().is_unspecified() || local.ip().is_multicast() {
        return Err("UDP owner candidate requires one exact, non-wildcard bind".into());
    }
    if matches!(local.ip(), IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some()) {
        return Err("IPv4-mapped IPv6 local bind is ambiguous".into());
    }
    Ok(())
}

fn unique_pid(rows: &[UdpOwnerRow], local: SocketAddr) -> Result<Option<u32>, String> {
    let mut candidate = None;
    for row in rows {
        if row.local != local {
            continue;
        }
        if row.pid == 0 {
            return Err("Matching UDP bind PID unavailable".into());
        }
        // SO_REUSEADDR and table races can produce duplicate local binds.
        // Even identical PIDs do not authenticate a unique socket.
        if candidate.is_some() {
            return Err("Duplicate UDP local bind: candidate is ambiguous".into());
        }
        candidate = Some(row.pid);
    }
    Ok(candidate)
}

fn stable_candidate(local: SocketAddr) -> Result<Option<ProcessEvidence>, String> {
    validate_local(local)?;
    let first = snapshot(local)?;
    let Some(pid) = unique_pid(&first, local)? else {
        return Ok(None);
    };
    let process = OwnedProcess::query(pid)?;
    let before = process.evidence()?;
    let second = snapshot(local)?;
    if unique_pid(&second, local)? != Some(pid) {
        return Err("UDP bind ownership changed between snapshots".into());
    }
    let after = process.evidence()?;
    if before != after || !process.is_active()? {
        return Err("UDP bind process object changed or exited".into());
    }
    Ok(Some(after))
}

fn assert_self_owned(local: SocketAddr) -> Result<(), String> {
    let candidate = stable_candidate(local)?
        .ok_or("Active UDP socket has no stable local-bind candidate")?;
    if candidate.pid != std::process::id()
        || candidate.created_100ns == 0
        || candidate.path.is_empty()
    {
        return Err("UDP socket owner does not match the live process object".into());
    }
    Ok(())
}

/// Real Windows UDP loopback send/receive + two actual IP Helper snapshots.
/// A successful result is NOT remote UDP-flow or NDISRD packet attribution.
pub fn self_test() -> Result<Value, String> {
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("IPv4 UDP sender bind failed: {e}"))?;
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("IPv4 UDP receiver bind failed: {e}"))?;
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("UDP receive deadline failed: {e}"))?;
    let bytes = [0x46, 0x42, 0x55, 0x44];
    let sent = sender
        .send_to(&bytes, receiver.local_addr().map_err(|e| e.to_string())?)
        .map_err(|e| format!("IPv4 UDP loopback send failed: {e}"))?;
    let mut received = [0u8; 8];
    let (count, from) = receiver
        .recv_from(&mut received)
        .map_err(|e| format!("IPv4 UDP loopback receive failed: {e}"))?;
    if sent != bytes.len()
        || count != bytes.len()
        || received[..count] != bytes
        || from != sender.local_addr().map_err(|e| e.to_string())?
    {
        return Err("IPv4 UDP loopback payload or sender tuple mismatch".into());
    }
    assert_self_owned(sender.local_addr().map_err(|e| e.to_string())?)?;
    assert_self_owned(receiver.local_addr().map_err(|e| e.to_string())?)?;

    // IPv6 is exercised when Windows permits an actual ::1 UDP bind. No
    // fabricated or skipped IPv6 success is reported on IPv4-only machines.
    let mut ipv6_available = false;
    if let Ok(socket6) = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
        ipv6_available = true;
        socket6
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| format!("IPv6 UDP receive deadline failed: {e}"))?;
        let local = socket6.local_addr().map_err(|e| e.to_string())?;
        if socket6.send_to(&bytes, local).map_err(|e| e.to_string())? != bytes.len() {
            return Err("IPv6 UDP loopback send was short".into());
        }
        let (received_len, source) = socket6
            .recv_from(&mut received)
            .map_err(|e| format!("IPv6 UDP loopback receive failed: {e}"))?;
        if received_len != bytes.len() || source != local || received[..received_len] != bytes {
            return Err("IPv6 UDP loopback payload or socket tuple mismatch".into());
        }
        assert_self_owned(local)?;
    }

    Ok(json!({
        "ok": true,
        "kind": "native_windows_iphelper_udp_local_bind_candidate",
        "actual_ipv4_loopback_udp_bytes": bytes.len(),
        "ipv4_sender_and_receiver_two_snapshots_consistent": true,
        "ipv6_loopback_available": ipv6_available,
        "ipv6_loopback_udp_and_two_snapshots_consistent": ipv6_available,
        "candidate_process_creation_epoch_checked": true,
        "process_identity_and_addresses_redacted": true,
        "udp_local_bind_only_not_remote_flow": true,
        "driver_opened": false,
        "native_ndisrd_packet_bound": false,
        "selected_app_accepted": false,
        "authorizes_capture": false,
        "protected_redirect_available": false,
        "dns_leak_free": false,
        "win10_11_acceptance": false,
        "release_accepted": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_zero_pid_duplicates_and_mapped_ipv6_never_bind_an_owner() {
        let local: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let row = UdpOwnerRow { local, pid: 123 };
        assert_eq!(unique_pid(&[row], local).unwrap(), Some(123));
        assert!(unique_pid(&[row, row], local).is_err());
        assert!(unique_pid(&[UdpOwnerRow { local, pid: 0 }], local).is_err());
        assert!(validate_local("0.0.0.0:54321".parse().unwrap()).is_err());
        assert!(validate_local("[::]:54321".parse().unwrap()).is_err());
        assert!(validate_local("[::ffff:127.0.0.1]:54321".parse().unwrap()).is_err());
        assert!(validate_local("127.0.0.1:0".parse().unwrap()).is_err());
    }

    #[test]
    fn udp_wire_port_and_ipv6_scope_are_network_order_and_exact() {
        let port_wire = u32::from_ne_bytes([0x12, 0x34, 0, 0]);
        assert_eq!(port(port_wire), 0x1234);
        let v4 = ipv4_row(MIB_UDPROW_OWNER_PID {
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: port_wire,
            dwOwningPid: 42,
        });
        assert_eq!(v4.local, "127.0.0.1:4660".parse().unwrap());
        let v6 = ipv6_row(MIB_UDP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
            dwLocalScopeId: 0,
            dwLocalPort: port_wire,
            dwOwningPid: 43,
        });
        assert_eq!(v6.local, "[::1]:4660".parse().unwrap());
        assert_ne!(unique_pid(&[UdpOwnerRow { local: v4.local, pid: 42 }], v6.local).unwrap(), Some(42));
    }

    #[test]
    fn actual_windows_udp_loopback_is_diagnostic_not_packet_authentication() {
        let v = self_test().expect("native dual-stack UDP owner canary");
        assert_eq!(v["ok"], true);
        assert_eq!(v["native_ndisrd_packet_bound"], false);
        assert_eq!(v["authorizes_capture"], false);
        assert_eq!(v["dns_leak_free"], false);
        assert_eq!(v["actual_ipv4_loopback_udp_bytes"], 4);
    }
}
