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
            Some((&input as *const u32).cast::<c_void>()),
            4,
            Some((&mut output as *mut u32).cast::<c_void>()),
            4,
            &mut returned,
            None,
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
        Err(ProbeProblem::IncompatibleVersion(version)) => {
            (true, false, Some(version), Some("incompatible_driver_api"), None)
        }
    };
    json!({
        "backend": "ndisapi",
        "device_opened": device_opened,
        "api_compatible": api_compatible,
        "driver_api_version": version.map(|v| format!("0x{v:08x}")),
        "error": error,
        "win32_error": win32_error,
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
