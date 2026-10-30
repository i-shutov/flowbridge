//! Read-only, Windows-only IP Helper TCP owner *candidate* lookup.
//! It does not authorize a capture verdict or claim packet-to-process proof.
//! Uses public Microsoft GetExtendedTcpTable / process query APIs exclusively.
//! The table can race socket creation/closure; ambiguous and changed rows fail
//! closed. No process image paths are written to logs or external artifacts.
#![cfg(windows)]

use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::ptr::{null_mut, read_unaligned};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FILETIME, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TABLE_ROWS: usize = 100_000;
const MAX_PROCESS_PATH_U16: usize = 32768;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnerQuery {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, PartialEq, Eq)]
struct TcpOwnerRow {
    local: SocketAddr,
    remote: SocketAddr,
    pid: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct ProcessEvidence {
    pid: u32,
    created_100ns: u64,
    path: String,
}

struct OwnedProcess(HANDLE);
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        // SAFETY: OpenProcess returned a non-null owned handle.
        unsafe { CloseHandle(self.0) };
    }
}

fn port(network_order_low_word: u32) -> u16 {
    u16::from_be(network_order_low_word as u16)
}

fn table_buffer(af: u32) -> Result<(Vec<u32>, usize), String> {
    let mut needed = 0u32;
    // SAFETY: No output buffer is provided; API returns required size.
    let first = unsafe {
        GetExtendedTcpTable(
            null_mut(),
            &mut needed,
            0,
            af,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER || needed < 4 {
        return Err(format!("IP Helper sizing failed: {first}"));
    }
    for _ in 0..4 {
        if needed as usize > MAX_TABLE_BYTES {
            return Err("IP Helper table exceeds bounded buffer".into());
        }
        let words = (needed as usize).div_ceil(size_of::<u32>());
        let mut output = vec![0u32; words];
        let mut size = (words * size_of::<u32>()) as u32;
        // SAFETY: Mutable aligned u32 buffer, exact capacity; no pointers are
        // retained by the synchronous API, and no other threads access it.
        let status = unsafe {
            GetExtendedTcpTable(
                output.as_mut_ptr().cast::<c_void>(),
                &mut size,
                0,
                af,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if status == 0 {
            if (size as usize) > output.len() * size_of::<u32>() {
                return Err("IP Helper reported oversized success".into());
            }
            return Ok((output, size as usize));
        }
        if status != ERROR_INSUFFICIENT_BUFFER || size <= needed {
            return Err(format!("IP Helper query failed: {status}"));
        }
        needed = size;
    }
    Err("IP Helper table changed too often".into())
}

fn decode_rows<R: Copy>(
    words: &[u32],
    used_bytes: usize,
    offset: usize,
    convert: impl Fn(R) -> TcpOwnerRow,
) -> Result<Vec<TcpOwnerRow>, String> {
    let row_bytes = size_of::<R>();
    if used_bytes < offset || words.is_empty() || row_bytes == 0 {
        return Err("IP Helper table header truncated".into());
    }
    let count = words[0] as usize;
    if count > MAX_TABLE_ROWS
        || count
            .checked_mul(row_bytes)
            .and_then(|n| n.checked_add(offset))
            .is_none_or(|end| end > used_bytes)
    {
        return Err("IP Helper table row count exceeds buffer".into());
    }
    let mut rows = Vec::with_capacity(count);
    for i in 0..count {
        let byte_index = offset + i * row_bytes;
        // SAFETY: Bounds were checked using count * size_of::<R>() + offset.
        // read_unaligned avoids assumptions about the table's row padding.
        let row =
            unsafe { read_unaligned(words.as_ptr().cast::<u8>().add(byte_index).cast::<R>()) };
        rows.push(convert(row));
    }
    Ok(rows)
}

fn ipv4_row(row: MIB_TCPROW_OWNER_PID) -> TcpOwnerRow {
    TcpOwnerRow {
        local: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            port(row.dwLocalPort),
        ),
        remote: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
            port(row.dwRemotePort),
        ),
        pid: row.dwOwningPid,
    }
}

fn ipv6_row(row: MIB_TCP6ROW_OWNER_PID) -> TcpOwnerRow {
    TcpOwnerRow {
        local: SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(row.ucLocalAddr),
            port(row.dwLocalPort),
            0,
            u32::from_be(row.dwLocalScopeId),
        )),
        remote: SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(row.ucRemoteAddr),
            port(row.dwRemotePort),
            0,
            u32::from_be(row.dwRemoteScopeId),
        )),
        pid: row.dwOwningPid,
    }
}

fn read_rows(af: u32) -> Result<Vec<TcpOwnerRow>, String> {
    let (data, used) = table_buffer(af)?;
    match af {
        x if x == AF_INET as u32 => decode_rows(
            &data,
            used,
            offset_of!(MIB_TCPTABLE_OWNER_PID, table),
            ipv4_row,
        ),
        x if x == AF_INET6 as u32 => decode_rows(
            &data,
            used,
            offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
            ipv6_row,
        ),
        _ => Err("Unsupported IP address family".into()),
    }
}

fn match_single_pid(rows: &[TcpOwnerRow], query: &OwnerQuery) -> Result<Option<u32>, String> {
    let mut candidate = None;
    for row in rows {
        if row.local != query.local || row.remote != query.remote {
            continue;
        }
        if row.pid == 0 {
            return Err("Zero PID in matching endpoint".into());
        }
        if candidate.is_some_and(|existing| existing != row.pid) {
            return Err("Ambiguous owning PIDs for the same TCP tuple".into());
        }
        candidate = Some(row.pid);
    }
    Ok(candidate)
}

fn require_stable_pid(
    rows: &[TcpOwnerRow],
    query: &OwnerQuery,
    expected: u32,
) -> Result<(), String> {
    if match_single_pid(rows, query)? != Some(expected) {
        return Err("TCP ownership changed during snapshot verification".into());
    }
    Ok(())
}

fn process_evidence(process: HANDLE, pid: u32) -> Result<ProcessEvidence, String> {
    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exited = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: Live process handle with query rights and four writable FILETIMEs.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(format!("GetProcessTimes failed: {}", unsafe {
            GetLastError()
        }));
    }
    let created_100ns =
        (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if created_100ns == 0 {
        return Err("Invalid process creation timestamp".into());
    }
    let mut name = vec![0u16; MAX_PROCESS_PATH_U16];
    let mut len = name.len() as u32;
    // SAFETY: Query into an allocated and bounded UTF-16 buffer.
    if unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut len) } == 0 {
        return Err(format!("QueryFullProcessImageNameW failed: {}", unsafe {
            GetLastError()
        }));
    }
    if len == 0 || len as usize > name.len() {
        return Err("Invalid process image name length".into());
    }
    let path = String::from_utf16(&name[..len as usize])
        .map_err(|_| "Invalid UTF-16 process image name")?;
    Ok(ProcessEvidence {
        pid,
        created_100ns,
        path,
    })
}

/// A diagnostic-only read. The returned identity MUST NOT be used to authorize
/// transparent capture: an IP Helper snapshot is not a packet ownership token.
pub(super) fn lookup(query: OwnerQuery) -> Result<Value, String> {
    if query.local.is_ipv4() != query.remote.is_ipv4() {
        return Err("Mixed address families are not a single TCP tuple".into());
    }
    if query.local.port() == 0 || query.remote.port() == 0 {
        return Err("TCP owner lookup requires nonzero ports".into());
    }
    let af = if query.local.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    } as u32;
    let first = read_rows(af)?;
    let pid = match match_single_pid(&first, &query)? {
        Some(pid) => pid,
        None => {
            return Ok(json!({
                "found": false, "authorizes_capture": false, "source": "iphelper_tcp_snapshot"
            }))
        }
    };
    // SAFETY: PROCESS_QUERY_LIMITED_INFORMATION, no modification access,
    // no handle inheritance. This handle pins the process object through the
    // second ownership observation, independently of later PID recycling.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(format!("OpenProcess query denied: {}", unsafe {
            GetLastError()
        }));
    }
    let handle = OwnedProcess(raw);
    let before = process_evidence(handle.0, pid)?;
    let second = read_rows(af)?;
    require_stable_pid(&second, &query, pid)?;
    let after = process_evidence(handle.0, pid)?;
    if before != after {
        return Err("Process identity changed during lookup".into());
    }
    Ok(json!({
        "found": true,
        "pid": before.pid,
        "process_creation_100ns": before.created_100ns,
        "executable_path": before.path,
        "source": "iphelper_tcp_snapshot",
        "two_snapshots_consistent": true,
        "authorizes_capture": false,
        "native_packet_attribution_proved": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn byte_order_and_tuple_matching_are_exact() {
        assert_eq!(port(0x5000), 80);
        let v4 = MIB_TCPROW_OWNER_PID {
            dwState: 5,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: 0x5000,
            dwRemoteAddr: u32::from_ne_bytes([192, 0, 2, 8]),
            dwRemotePort: 0xbb01,
            dwOwningPid: 42,
        };
        let row = ipv4_row(v4);
        assert_eq!(row.local.to_string(), "127.0.0.1:80");
        assert_eq!(row.remote.ip().to_string(), "192.0.2.8");
        let query = OwnerQuery {
            local: row.local,
            remote: row.remote,
        };
        assert_eq!(match_single_pid(&[row], &query).unwrap(), Some(42));
        let wrong = OwnerQuery {
            local: query.local,
            remote: SocketAddr::new(query.remote.ip(), query.remote.port() + 1),
        };
        assert_eq!(match_single_pid(&[ipv4_row(v4)], &wrong).unwrap(), None);
    }

    #[test]
    fn ambiguous_pid_and_bad_buffer_fail_closed() {
        let query = OwnerQuery {
            local: "127.0.0.1:12345".parse().unwrap(),
            remote: "127.0.0.1:23456".parse().unwrap(),
        };
        let first = TcpOwnerRow {
            local: query.local,
            remote: query.remote,
            pid: 3,
        };
        let second = TcpOwnerRow {
            local: query.local,
            remote: query.remote,
            pid: 4,
        };
        assert!(match_single_pid(&[first, second], &query).is_err());
        assert!(require_stable_pid(
            &[TcpOwnerRow {
                local: query.local,
                remote: query.remote,
                pid: 4
            }],
            &query,
            3
        )
        .is_err());
        assert!(require_stable_pid(&[], &query, 3).is_err());
        assert!(require_stable_pid(
            &[TcpOwnerRow {
                local: query.local,
                remote: query.remote,
                pid: 3
            }],
            &query,
            3
        )
        .is_ok());
        assert!(match_single_pid(
            &[TcpOwnerRow {
                local: query.local,
                remote: query.remote,
                pid: 0,
            }],
            &query
        )
        .is_err());
        let truncated = decode_rows::<MIB_TCPROW_OWNER_PID>(&[500], 4, 4, ipv4_row);
        assert!(truncated.is_err());
    }

    #[test]
    fn real_local_tcp_socket_has_process_candidate_but_never_capture_proof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let query = OwnerQuery {
            local: client.local_addr().unwrap(),
            remote: client.peer_addr().unwrap(),
        };
        let result = lookup(query).unwrap();
        assert_eq!(result["found"], true);
        assert_eq!(result["pid"], std::process::id());
        assert!(result["process_creation_100ns"].as_u64().unwrap() > 0);
        assert!(result["executable_path"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .ends_with(".exe"));
        assert_eq!(result["authorizes_capture"], false);
        assert_eq!(result["native_packet_attribution_proved"], false);
    }
}
