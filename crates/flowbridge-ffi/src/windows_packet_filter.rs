//! Original, read-only probe for the separately installed Windows Packet Filter
//! device. This module does not load drivers or capture/inject packets.
//!
//! Only the published NDISRD device ABI is used; no ProxiFyre source is linked,
//! copied, translated or called. An API version response is NOT proof of a
//! Microsoft signature, correct routing, DNS privacy or secure installation.
#![cfg(windows)]

use serde_json::{json, Value};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

const DEVICE: &str = r"\\.\NDISRD";
const FILE_DEVICE_NDISRD: u32 = 0x8300;
const GET_VERSION_FUNCTION: u32 = 0x830;
// CTL_CODE(device, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
const GET_VERSION_IOCTL: u32 = (FILE_DEVICE_NDISRD << 16) | (GET_VERSION_FUNCTION << 2);
// Public NDISRD ABI: IOCTL_NDISRD_GET_TCPIP_INTERFACES is function index + 1.
const GET_ADAPTERS_IOCTL: u32 = (FILE_DEVICE_NDISRD << 16) | ((GET_VERSION_FUNCTION + 1) << 2);
const ADAPTER_CAPACITY: usize = 32;
const ADAPTER_NAME_BYTES: usize = 256;
const MAC_BYTES: usize = 6;
const REQUIRED_MAJOR: u16 = 3;
const MINIMUM_MINOR: u16 = 0x0601;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeProblem {
    Open(u32),
    VersionRequest(u32),
    UnexpectedReplyLength(u32),
    IncompatibleVersion(u32),
}

fn compatible(version: u32) -> bool {
    let major = ((version >> 12) & 0xF) as u16;
    let minor = (version >> 16) as u16;
    major == REQUIRED_MAJOR && minor >= MINIMUM_MINOR
}

/// No privileged service start, driver installation or device modification.
/// Opening without requested read/write access is allowed for a passive
/// version query on supported NDISRD drivers.
fn read_version() -> Result<u32, ProbeProblem> {
    let wide: Vec<u16> = DEVICE.encode_utf16().chain(Some(0)).collect();
    // SAFETY: NUL-terminated UTF-16 path, no access requested, and no handle
    // inheritance. Windows validates the device object and handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: The failing API sets the calling thread's Win32 error.
        return Err(ProbeProblem::Open(unsafe { GetLastError() }));
    }

    let input: u32 = u32::MAX;
    let mut output: u32 = 0;
    let mut returned: u32 = 0;
    // SAFETY: Both buffers are in-process u32 values, remain alive for the
    // synchronous DeviceIoControl and use their exact byte sizes.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            GET_VERSION_IOCTL,
            (&input as *const u32).cast::<c_void>(),
            std::mem::size_of::<u32>() as u32,
            (&mut output as *mut u32).cast::<c_void>(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let error = if ok == 0 {
        // SAFETY: Error captured BEFORE closing the handle.
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    // SAFETY: Handle was returned by a successful CreateFileW call.
    unsafe { CloseHandle(handle) };
    if let Some(error) = error {
        return Err(ProbeProblem::VersionRequest(error));
    }
    if returned != 4 {
        return Err(ProbeProblem::UnexpectedReplyLength(returned));
    }
    if !compatible(output) {
        return Err(ProbeProblem::IncompatibleVersion(output));
    }
    Ok(output)
}

// The vendor's public, x64 TCP_AdapterList wire ABI. No vendor library is
// linked, and opaque adapter handles never leave this diagnostic module.
// Offsets and size are asserted below: the native driver accepts one complete
// fixed-size buffer, not an unbounded vector or a structure of host pointers.
#[repr(C)]
#[derive(Default)]
struct AdapterList {
    count: u32,
    names: [[u8; ADAPTER_NAME_BYTES]; ADAPTER_CAPACITY],
    handles: [usize; ADAPTER_CAPACITY],
    media: [u32; ADAPTER_CAPACITY],
    macs: [[u8; MAC_BYTES]; ADAPTER_CAPACITY],
    mtu: [u16; ADAPTER_CAPACITY],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterQueryProblem {
    #[cfg(not(target_pointer_width = "64"))]
    UnsupportedArchitecture,
    Open(u32),
    Query(u32),
    ReplySize(u32),
    Count(u32),
    Name(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct AdapterDiagnostic {
    name: String,
    medium: u32,
    mtu: u16,
    mac: [u8; MAC_BYTES],
    handle_present: bool,
}

impl AdapterQueryProblem {
    fn message(self) -> String {
        match self {
            #[cfg(not(target_pointer_width = "64"))]
            Self::UnsupportedArchitecture => "unsupported_architecture".to_owned(),
            Self::Open(code) => format!("device_open_failed:{code}"),
            Self::Query(code) => format!("adapter_query_failed:{code}"),
            Self::ReplySize(bytes) => format!("unexpected_reply_size:{bytes}"),
            Self::Count(count) => format!("invalid_adapter_count:{count}"),
            Self::Name(index) => format!("invalid_adapter_name:{index}"),
        }
    }
}

fn validate_adapter_reply(
    reply: &AdapterList,
    returned: u32,
) -> Result<Vec<AdapterDiagnostic>, AdapterQueryProblem> {
    if returned as usize != std::mem::size_of::<AdapterList>() {
        return Err(AdapterQueryProblem::ReplySize(returned));
    }
    if reply.count as usize > ADAPTER_CAPACITY {
        return Err(AdapterQueryProblem::Count(reply.count));
    }
    let mut adapters: Vec<AdapterDiagnostic> = Vec::with_capacity(reply.count as usize);
    for (index, bytes) in reply.names[..reply.count as usize].iter().enumerate() {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .filter(|end| *end > 0)
            .ok_or(AdapterQueryProblem::Name(index))?;
        // Internal adapter names should be printable ASCII. Refuse a malformed
        // or truncated name rather than treating ambiguous identity as usable.
        if !bytes[..end].iter().all(|byte| byte.is_ascii_graphic()) {
            return Err(AdapterQueryProblem::Name(index));
        }
        let name =
            std::str::from_utf8(&bytes[..end]).map_err(|_| AdapterQueryProblem::Name(index))?;
        if adapters
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(name))
        {
            return Err(AdapterQueryProblem::Name(index));
        }
        adapters.push(AdapterDiagnostic {
            name: name.to_owned(),
            medium: reply.media[index],
            mtu: reply.mtu[index],
            mac: reply.macs[index],
            handle_present: reply.handles[index] != 0,
        });
    }
    Ok(adapters)
}

/// Passive IOCTL only. Neither opens an adapter for filtering nor enables
/// listen/tunnel modes, queue events, packet reads or injection.
#[cfg(target_pointer_width = "64")]
fn read_bound_adapters() -> Result<Vec<AdapterDiagnostic>, AdapterQueryProblem> {
    let wide: Vec<u16> = DEVICE.encode_utf16().chain(Some(0)).collect();
    // SAFETY: The literal device name is NUL-terminated UTF-16, requesting
    // zero file access and no handle inheritance.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: A failing Win32 call sets the current thread's error.
        return Err(AdapterQueryProblem::Open(unsafe { GetLastError() }));
    }
    let input = AdapterList::default();
    let mut output = AdapterList::default();
    let mut returned = 0;
    let size = std::mem::size_of::<AdapterList>() as u32;
    // SAFETY: Input and output are separate fully initialized fixed-layout
    // buffers, both alive for this synchronous buffered IOCTL.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            GET_ADAPTERS_IOCTL,
            (&input as *const AdapterList).cast::<c_void>(),
            size,
            (&mut output as *mut AdapterList).cast::<c_void>(),
            size,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let error = if ok == 0 {
        // SAFETY: Capture the failure before CloseHandle overwrites it.
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    // SAFETY: Handle came from successful CreateFileW.
    unsafe { CloseHandle(handle) };
    if let Some(code) = error {
        return Err(AdapterQueryProblem::Query(code));
    }
    validate_adapter_reply(&output, returned)
}

#[cfg(not(target_pointer_width = "64"))]
fn read_bound_adapters() -> Result<Vec<AdapterDiagnostic>, AdapterQueryProblem> {
    Err(AdapterQueryProblem::UnsupportedArchitecture)
}

pub(super) fn report() -> Value {
    let status = read_version();
    let (device_opened, api_compatible, version, error, win32_error) = match status {
        Ok(version) => (true, true, Some(version), None, None),
        Err(ProbeProblem::Open(code)) => {
            (false, false, None, Some("device_open_failed"), Some(code))
        }
        Err(ProbeProblem::VersionRequest(code)) => {
            (true, false, None, Some("version_query_failed"), Some(code))
        }
        Err(ProbeProblem::UnexpectedReplyLength(_)) => {
            (true, false, None, Some("invalid_version_reply"), None)
        }
        Err(ProbeProblem::IncompatibleVersion(version)) => (
            true,
            false,
            Some(version),
            Some("incompatible_driver_api"),
            None,
        ),
    };
    let (adapter_inventory_status, adapter_inventory, adapter_error) = if api_compatible {
        match read_bound_adapters() {
            Ok(names) => ("read_only_ok", Some(names), None),
            Err(problem) => ("failed", None, Some(problem.message())),
        }
    } else {
        ("not_checked", None, None)
    };
    let adapter_count = adapter_inventory.as_ref().map(Vec::len);
    json!({
        "backend": "ndisapi",
        "device_opened": device_opened,
        "api_compatible": api_compatible,
        "driver_api_version": version.map(|v| format!("0x{v:08x}")),
        "error": error,
        "win32_error": win32_error,
        "adapter_inventory_status": adapter_inventory_status,
        "adapter_count": adapter_count,
        "adapter_inventory": adapter_inventory,
        "adapter_query_error": adapter_error,
        "signature_status": "not_checked",
        "driver_installation_attempted": false,
        "packet_capture_active": false,
        "native_routing_accepted": false,
        "dns_leak_test_passed": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn driver_version_acceptance_requires_major_three_and_minor_at_least_0601() {
        assert!(compatible(0x06013000));
        assert!(compatible(0x06023000));
        assert!(!compatible(0x06003000));
        assert!(!compatible(0x06014000));
        assert!(!compatible(0x06012000));
        assert!(!compatible(0));
        assert_eq!(GET_VERSION_IOCTL, 0x830020c0);
    }

    #[test]
    fn adapter_abi_x64_layout_and_ioctl_are_pinned() {
        assert_eq!(GET_ADAPTERS_IOCTL, 0x830020c4);
        assert_eq!(ADAPTER_CAPACITY, 32);
        assert_eq!(ADAPTER_NAME_BYTES, 256);
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::align_of::<AdapterList>(), 8);
            assert_eq!(std::mem::size_of::<AdapterList>(), 8840);
            assert_eq!(std::mem::offset_of!(AdapterList, names), 4);
            assert_eq!(std::mem::offset_of!(AdapterList, handles), 8200);
            assert_eq!(std::mem::offset_of!(AdapterList, media), 8456);
            assert_eq!(std::mem::offset_of!(AdapterList, macs), 8584);
            assert_eq!(std::mem::offset_of!(AdapterList, mtu), 8776);
        }
    }

    #[test]
    fn adapter_reply_rejects_truncation_count_and_ambiguous_names() {
        let mut reply = AdapterList::default();
        let full = std::mem::size_of::<AdapterList>() as u32;
        assert_eq!(
            validate_adapter_reply(&reply, full).unwrap(),
            Vec::<AdapterDiagnostic>::new()
        );
        assert_eq!(
            validate_adapter_reply(&reply, full - 1),
            Err(AdapterQueryProblem::ReplySize(full - 1))
        );
        reply.count = 33;
        assert_eq!(
            validate_adapter_reply(&reply, full),
            Err(AdapterQueryProblem::Count(33))
        );
        reply.count = 1;
        assert_eq!(
            validate_adapter_reply(&reply, full),
            Err(AdapterQueryProblem::Name(0))
        );
        reply.names[0].fill(b'A');
        assert_eq!(
            validate_adapter_reply(&reply, full),
            Err(AdapterQueryProblem::Name(0))
        );
        reply.names[0] = [0; ADAPTER_NAME_BYTES];
        reply.names[0][..14].copy_from_slice(br"\DEVICE\{TEST}");
        assert_eq!(
            validate_adapter_reply(&reply, full)
                .unwrap()
                .into_iter()
                .map(|adapter| adapter.name)
                .collect::<Vec<_>>(),
            vec![r"\DEVICE\{TEST}".to_owned()]
        );
        reply.count = 2;
        reply.names[1] = reply.names[0];
        assert_eq!(
            validate_adapter_reply(&reply, full),
            Err(AdapterQueryProblem::Name(1))
        );
        reply.names[1][1] = b'd'; // Windows adapter names are case-insensitive.
        assert_eq!(
            validate_adapter_reply(&reply, full),
            Err(AdapterQueryProblem::Name(1))
        );
        reply.names[1][0] = 0xff;
        assert_eq!(
            validate_adapter_reply(&reply, full),
            Err(AdapterQueryProblem::Name(1))
        );
    }

    #[test]
    fn probe_never_makes_capture_or_signature_claims() {
        let report = report();
        assert_eq!(report["backend"], "ndisapi");
        assert_eq!(report["signature_status"], "not_checked");
        assert_eq!(report["packet_capture_active"], false);
        assert_eq!(report["native_routing_accepted"], false);
        assert_eq!(report["dns_leak_test_passed"], false);
        assert_eq!(report["driver_installation_attempted"], false);
    }
}
