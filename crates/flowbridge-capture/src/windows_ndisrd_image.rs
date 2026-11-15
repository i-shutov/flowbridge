//! Read-only Windows SCM configuration receipt for a separately installed NDISRD.
//! No service/driver/filter mutation, no network I/O and NO kernel PacketBound.
//! A configured on-disk filename is never a signature, loaded-image or
//! per-packet process provenance claim.
#![cfg(windows)]

use serde_json::{json, Value};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QUERY_SERVICE_CONFIGW,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
};

const MAX_CONFIG_BYTES: usize = 8192;
const NDISRD: &str = "NDISRD";

struct OwnedScm(SC_HANDLE);
impl Drop for OwnedScm {
    fn drop(&mut self) {
        // SAFETY: Only a successfully opened service/SCM handle is wrapped.
        unsafe { CloseServiceHandle(self.0) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigError {
    OpenScm(u32),
    OpenService(u32),
    QueryConfig(u32),
    InvalidConfig,
}

fn config_image(name: &str) -> Result<String, ConfigError> {
    let raw_scm =
        unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if raw_scm.is_null() {
        return Err(ConfigError::OpenScm(unsafe { GetLastError() }));
    }
    let scm = OwnedScm(raw_scm);
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let raw_service = unsafe { OpenServiceW(scm.0, wide.as_ptr(), SERVICE_QUERY_CONFIG) };
    if raw_service.is_null() {
        return Err(ConfigError::OpenService(unsafe { GetLastError() }));
    }
    let service = OwnedScm(raw_service);

    // QUERY_SERVICE_CONFIGW contains embedded POINTERS into caller memory.
    // Vec<usize> is aligned for the structure even on Windows x64; Vec<u8>
    // would only promise alignment 1 and would be unsound to cast here.
    let mut storage = vec![0usize; MAX_CONFIG_BYTES / std::mem::size_of::<usize>()];
    let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    let mut needed = 0;
    let success = unsafe {
        QueryServiceConfigW(service.0, config, MAX_CONFIG_BYTES as u32, &mut needed)
    };
    if success == 0 {
        return Err(ConfigError::QueryConfig(unsafe { GetLastError() }));
    }
    // Never dereference an unchecked pointer returned in a data structure.
    // The SCM is local, but its config may have been modified in the registry.
    let ptr = unsafe { (*config).lpBinaryPathName } as usize;
    let begin = storage.as_ptr() as usize;
    let end = begin + MAX_CONFIG_BYTES;
    if ptr < begin || ptr >= end || ptr % std::mem::align_of::<u16>() != 0 {
        return Err(ConfigError::InvalidConfig);
    }
    let available = ((end - ptr) / std::mem::size_of::<u16>()).min(1025);
    let raw = unsafe { std::slice::from_raw_parts(ptr as *const u16, available) };
    let length = raw.iter().position(|unit| *unit == 0).ok_or(ConfigError::InvalidConfig)?;
    if length == 0 || length > 1024 {
        return Err(ConfigError::InvalidConfig);
    }
    let path = String::from_utf16(&raw[..length]).map_err(|_| ConfigError::InvalidConfig)?;
    Ok(path)
}

fn path_hint(raw: &str) -> Option<&str> {
    let value = raw.trim().trim_matches('"');
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if !lower.ends_with(".sys") || lower.starts_with(r"\\") || lower.starts_with(r"\device\")
        || lower.split('\\').any(|part| part == "..")
    {
        return None;
    }
    let basename = value.rsplit(['\\', '/']).next()?;
    if basename.is_empty() || !basename.to_ascii_lowercase().ends_with(".sys") {
        return None;
    }
    Some(basename)
}

fn classify(result: Result<String, ConfigError>) -> Value {
    let mut report = json!({
        "source":"scm_query_config",
        "service_name":NDISRD,
        "read_only":true,
        "configured_image_observed":false,
        "configured_image_basename":null,
        "configured_image_status":"unknown",
        "win32_error":null,
        "image_sha256_checked":false,
        "image_signing_verified":false,
        "loaded_driver_image_attested":false,
        "packet_process_epoch_available":false,
        "ndisrd_kernel_connection_id_available":false,
        "protected_capture_authorized":false,
        "g2_accepted":false,
        "release_accepted":false,
    });
    match result {
        Ok(config) => {
            if let Some(name) = path_hint(&config) {
                report["configured_image_observed"] = json!(true);
                report["configured_image_basename"] = json!(name);
                report["configured_image_status"] = json!("observed_only");
            } else {
                report["configured_image_status"] = json!("invalid_or_ambiguous");
            }
        }
        Err(ConfigError::OpenService(1060)) => {
            report["configured_image_status"] = json!("service_not_installed");
        }
        Err(error) => {
            let (category, code) = match error {
                ConfigError::OpenScm(code) => ("scm_open_failed", Some(code)),
                ConfigError::OpenService(code) => ("service_open_failed", Some(code)),
                ConfigError::QueryConfig(code) => ("service_config_query_failed", Some(code)),
                ConfigError::InvalidConfig => ("invalid_config_pointer_or_string", None),
            };
            report["configured_image_status"] = json!(category);
            if let Some(code) = code {
                report["win32_error"] = json!(code);
            }
        }
    }
    report
}

pub(super) fn report() -> Value {
    classify(config_image(NDISRD))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_kernel_driver_never_grants_packet_ownership_or_signing() {
        let observed = classify(Ok(r"\SystemRoot\System32\drivers\ndisrd.sys".to_string()));
        assert_eq!(observed["configured_image_observed"], true);
        assert_eq!(observed["configured_image_basename"], "ndisrd.sys");
        for gate in [
            "image_sha256_checked", "image_signing_verified",
            "loaded_driver_image_attested", "packet_process_epoch_available",
            "ndisrd_kernel_connection_id_available", "protected_capture_authorized",
            "g2_accepted", "release_accepted",
        ] {
            assert_eq!(observed[gate], false);
        }
        let absent = classify(Err(ConfigError::OpenService(1060)));
        assert_eq!(absent["configured_image_status"], "service_not_installed");
        assert_eq!(absent["g2_accepted"], false);
        let denied = classify(Err(ConfigError::OpenService(5)));
        assert_eq!(denied["configured_image_status"], "service_open_failed");
        assert_eq!(denied["win32_error"], 5);
        assert_eq!(denied["configured_image_observed"], false);
    }

    #[test]
    fn invalid_or_ambiguous_service_path_fails_read_only() {
        for value in [
            "", r"..\fake.sys", r"\\server\ndisrd.sys", r"\Device\volume\ndisrd.sys",
            r"C:\Windows\drivers\..\evil.sys", r"C:\Windows\ndisrd.exe",
            "bad\0driver.sys",
        ] {
            assert!(path_hint(value).is_none(), "unsafe path: {value:?}");
        }
        assert_eq!(path_hint(r"C:\Windows\System32\drivers\NDISRD.sys"), Some("NDISRD.sys"));
    }

    #[test]
    fn real_native_windows_system_driver_config_is_only_observation() {
        // On hosted Windows, TCPIP is a real installed system kernel driver.
        // Its filename is read with QUERY_CONFIG only. It is NOT NDISRD.
        let tcp = config_image("Tcpip").expect("Windows TCPIP SCM config unavailable");
        assert_eq!(path_hint(&tcp).map(str::to_ascii_lowercase).as_deref(), Some("tcpip.sys"));
        let ndis = report();
        assert_eq!(ndis["read_only"], true);
        assert_eq!(ndis["packet_process_epoch_available"], false);
        assert_eq!(ndis["protected_capture_authorized"], false);
    }
}
