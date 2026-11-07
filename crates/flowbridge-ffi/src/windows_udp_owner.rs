//! Read-only Windows UDP bind owner candidate (IPv4/IPv6).
//! A UDP table has NO remote endpoint: the PID identifies a binder, NOT
//! the origin of a particular datagram, DNS query or captured packet.
//! Every result is diagnostic-only and permanently denies capture authority.
#![cfg(windows)]

use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::c_void;
use std::mem::{offset_of, size_of, size_of_val};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::ptr::{null_mut, read_unaligned};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::windows_tcp_owner::OwnedProcess;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TABLE_ROWS: usize = 100_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UdpOwnerQuery {
    pub local: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UdpBindRow {
    local: SocketAddr,
    pid: u32,
}

fn port(network_order_low_word: u32) -> u16 {
    u16::from_be(network_order_low_word as u16)
}

fn ipv4_row(row: MIB_UDPROW_OWNER_PID) -> UdpBindRow {
    UdpBindRow {
        local: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            port(row.dwLocalPort),
        ),
        pid: row.dwOwningPid,
    }
}

fn ipv6_row(row: MIB_UDP6ROW_OWNER_PID) -> UdpBindRow {
    UdpBindRow {
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
    // SAFETY: Null output with valid sizing pointer is the documented
    // GetExtendedUdpTable two-call protocol; no system configuration changes.
    let first =
        unsafe { GetExtendedUdpTable(null_mut(), &mut needed, 0, af, UDP_TABLE_OWNER_PID, 0) };
    if first != ERROR_INSUFFICIENT_BUFFER || needed < 4 {
        return Err(format!("UDP IP Helper sizing failed: {first}"));
    }
    for _ in 0..4 {
        if needed as usize > MAX_TABLE_BYTES {
            return Err("UDP table exceeds bounded buffer".into());
        }
        let capacity_words = (needed as usize).div_ceil(size_of::<u32>());
        let mut words = vec![0u32; capacity_words];
        let mut allocated_bytes = (capacity_words * size_of::<u32>()) as u32;
        // SAFETY: A u32 Vec provides 4-byte alignment. No pointer is retained
        // by the synchronous API; its actual writable capacity is supplied.
        let rc = unsafe {
            GetExtendedUdpTable(
                words.as_mut_ptr().cast::<c_void>(),
                &mut allocated_bytes,
                0,
                af,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if rc == 0 {
            if allocated_bytes as usize > words.len() * size_of::<u32>() {
                return Err("UDP table reported oversized success".into());
            }
            return Ok((words, allocated_bytes as usize));
        }
        if rc != ERROR_INSUFFICIENT_BUFFER || allocated_bytes <= needed {
            return Err(format!("UDP IP Helper query failed: {rc}"));
        }
        needed = allocated_bytes;
    }
    Err("UDP IP Helper table changed too often".into())
}

fn decode_rows<R: Copy>(
    words: &[u32],
    used: usize,
    offset: usize,
    convert: impl Fn(R) -> UdpBindRow,
) -> Result<Vec<UdpBindRow>, String> {
    if words.is_empty() || used < offset || used > size_of_val(words) {
        return Err("UDP table header truncated".into());
    }
    let count = words[0] as usize;
    let row_size = size_of::<R>();
    if row_size == 0
        || count > MAX_TABLE_ROWS
        || count
            .checked_mul(row_size)
            .and_then(|bytes| bytes.checked_add(offset))
            .is_none_or(|end| end > used)
    {
        return Err("UDP table row count exceeds buffer".into());
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let byte_index = offset + index * row_size;
        // SAFETY: The checked length and offset keep every row in the u32
        // allocation; unaligned read accounts for SDK table padding.
        let raw =
            unsafe { read_unaligned(words.as_ptr().cast::<u8>().add(byte_index).cast::<R>()) };
        rows.push(convert(raw));
    }
    Ok(rows)
}

fn read_rows(af: u32) -> Result<Vec<UdpBindRow>, String> {
    let (words, used) = read_table(af)?;
    if af == AF_INET as u32 {
        decode_rows(
            &words,
            used,
            offset_of!(MIB_UDPTABLE_OWNER_PID, table),
            ipv4_row,
        )
    } else if af == AF_INET6 as u32 {
        decode_rows(
            &words,
            used,
            offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
            ipv6_row,
        )
    } else {
        Err("Unsupported UDP address family".into())
    }
}

/// Exact local bind only. A wildcard bind is deliberately NOT expanded to any
/// destination/interface; reuse or duplicate rows are refused even for one PID.
fn unique_bind_pid(rows: &[UdpBindRow], local: SocketAddr) -> Result<Option<u32>, String> {
    let mut candidate = None;
    for row in rows {
        if row.local != local {
            continue;
        }
        if row.pid == 0 {
            return Err("UDP bind owner PID is zero".into());
        }
        if candidate.replace(row.pid).is_some() {
            return Err("Ambiguous UDP bind: multiple identical endpoint rows".into());
        }
    }
    Ok(candidate)
}

fn require_stable_bind(
    rows: &[UdpBindRow],
    local: SocketAddr,
    expected_pid: u32,
) -> Result<(), String> {
    if unique_bind_pid(rows, local)? != Some(expected_pid) {
        return Err("UDP binding changed during IP Helper snapshots".into());
    }
    Ok(())
}

/// The diagnostics API never yields a flow or packet authorization.
/// UDP remote endpoints, per-packet provenance and leakage are not observable
/// through GetExtendedUdpTable.
pub(super) fn lookup(query: UdpOwnerQuery) -> Result<Value, String> {
    if query.local.port() == 0 {
        return Err("UDP binding lookup requires a nonzero local port".into());
    }
    let af = if query.local.is_ipv4() {
        AF_INET as u32
    } else {
        AF_INET6 as u32
    };
    let first = read_rows(af)?;
    let pid = match unique_bind_pid(&first, query.local)? {
        Some(pid) => pid,
        None => {
            return Ok(json!({
                "found": false,
                "source": "iphelper_udp_bind_snapshot",
                "bind_only": true,
                "remote_endpoint_known": false,
                "authorizes_capture": false,
                "native_packet_attribution_proved": false,
                "dns_leak_test_passed": false
            }))
        }
    };

    // Query-only handle pins the same process object throughout the two
    // UDP bind snapshots. A bind is NOT an individual datagram owner.
    let handle = OwnedProcess::query(pid)?;
    let before = handle.evidence()?;
    let second = read_rows(af)?;
    require_stable_bind(&second, query.local, pid)?;
    let after = handle.evidence()?;
    if before != after {
        return Err("Process identity changed during UDP lookup".into());
    }

    Ok(json!({
        "found": true,
        "pid": before.pid,
        "process_creation_100ns": before.created_100ns,
        "executable_path": before.path,
        "local_bind": query.local.to_string(),
        "wildcard_bind": query.local.ip().is_unspecified(),
        "source": "iphelper_udp_bind_snapshot",
        "two_snapshots_consistent": true,
        "bind_only": true,
        "remote_endpoint_known": false,
        "authorizes_capture": false,
        "native_packet_attribution_proved": false,
        "dns_leak_test_passed": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn row(local: &str, pid: u32) -> UdpBindRow {
        UdpBindRow {
            local: local.parse().unwrap(),
            pid,
        }
    }

    #[test]
    fn v4_v6_bind_byte_order_is_exact() {
        assert_eq!(port(0x3500), 53);
        let v4 = MIB_UDPROW_OWNER_PID {
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: 0x3500,
            dwOwningPid: 40,
        };
        let v4row = ipv4_row(v4);
        assert_eq!(v4row.local.to_string(), "127.0.0.1:53");
        assert_eq!(v4row.pid, 40);
        let v6 = MIB_UDP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
            dwLocalScopeId: 0,
            dwLocalPort: 0x3500,
            dwOwningPid: 44,
        };
        let v6row = ipv6_row(v6);
        assert_eq!(v6row.local.to_string(), "[::1]:53");
        assert_eq!(v6row.pid, 44);
        assert_eq!(
            unique_bind_pid(&[v6row], "[::1]:53".parse().unwrap()).unwrap(),
            Some(44)
        );
    }

    #[test]
    fn multiple_binders_zero_pid_missing_or_changed_rows_are_denied() {
        let local: SocketAddr = "0.0.0.0:51000".parse().unwrap();
        assert_eq!(unique_bind_pid(&[], local).unwrap(), None);
        assert!(unique_bind_pid(&[row("0.0.0.0:51000", 0)], local).is_err());
        assert!(
            unique_bind_pid(&[row("0.0.0.0:51000", 10), row("0.0.0.0:51000", 10)], local).is_err()
        );
        assert!(
            unique_bind_pid(&[row("0.0.0.0:51000", 10), row("0.0.0.0:51000", 11)], local).is_err()
        );
        assert_eq!(
            unique_bind_pid(&[row("127.0.0.1:51000", 10)], local).unwrap(),
            None
        );
        assert!(require_stable_bind(&[], local, 10).is_err());
        assert!(require_stable_bind(&[row("0.0.0.0:51000", 11)], local, 10).is_err());
        assert!(require_stable_bind(&[row("0.0.0.0:51000", 10)], local, 10).is_ok());
    }

    #[test]
    fn overlarge_and_truncated_tables_are_rejected() {
        let offset = offset_of!(MIB_UDPTABLE_OWNER_PID, table);
        assert!(decode_rows::<MIB_UDPROW_OWNER_PID>(&[100_001], 4, offset, ipv4_row).is_err());
        assert!(decode_rows::<MIB_UDPROW_OWNER_PID>(&[1], 4, offset, ipv4_row).is_err());
        assert!(decode_rows::<MIB_UDPROW_OWNER_PID>(&[0], 0, offset, ipv4_row).is_err());
    }

    #[test]
    fn live_windows_udp_bind_returns_pid_but_never_packet_authorization() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let result = lookup(UdpOwnerQuery {
            local: socket.local_addr().unwrap(),
        })
        .unwrap();
        assert_eq!(result["found"], true, "{result}");
        assert_eq!(result["pid"], std::process::id());
        assert!(result["process_creation_100ns"].as_u64().unwrap() > 0);
        assert_eq!(result["bind_only"], true);
        assert_eq!(result["remote_endpoint_known"], false);
        assert_eq!(result["authorizes_capture"], false);
        assert_eq!(result["native_packet_attribution_proved"], false);
        assert_eq!(result["dns_leak_test_passed"], false);
    }

    #[test]
    fn invalid_query_remote_key_and_zero_port_are_denied() {
        assert!(serde_json::from_str::<UdpOwnerQuery>(
            r#"{"local":"127.0.0.1:53","remote":"192.0.2.1:443"}"#
        )
        .is_err());
        assert!(lookup(UdpOwnerQuery {
            local: "127.0.0.1:0".parse().unwrap()
        })
        .is_err());
    }
}
