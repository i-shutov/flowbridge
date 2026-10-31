//! Explicit, rollback-aware SCM staging for the original Rust SOCKS service.
//! This manages only the fixed, on-demand user-mode FlowBridge candidate.
//! It never installs/starts a driver, starts the service, grants broad pipe
//! access, enables protected routing, or silently replaces an existing service.
#![cfg(windows)]

use serde_json::{json, Value};
use std::mem::size_of;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx, QUERY_SERVICE_CONFIGW, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_CHANGE_CONFIG,
    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};

const DELETE_ACCESS: u32 = 0x0001_0000;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const MAX_PATH_CHARS: usize = 4096;
const SERVICE_RIGHTS: u32 =
    SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE_ACCESS;

struct Handle(SC_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if (self.0 as usize) != 0 {
            // SAFETY: The SCM API returned this handle on success.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn err(action: &str) -> String {
    format!("{action} failed (Windows error {})", unsafe {
        GetLastError()
    })
}

// Arguments are never passed through cmd.exe. Still reject quoting/control
// characters to preserve a single, auditable SCM binary command-line grammar.
fn exact_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_PATH_CHARS
        || path.contains('"')
        || path.chars().any(char::is_control)
        || !Path::new(path).is_absolute()
    {
        return Err("SCM staging requires a bounded, absolute, unquoted path".into());
    }
    Ok(())
}

fn image_command(config: &str) -> Result<String, String> {
    exact_path(config)?;
    let exe = std::env::current_exe().map_err(|_| "current executable unavailable")?;
    let image = exe
        .to_str()
        .ok_or("current executable path is not Unicode")?;
    exact_path(image)?;
    if !exe.is_file() {
        return Err("current executable does not exist".into());
    }
    Ok(format!("\"{image}\" service-run \"{config}\""))
}

fn manager() -> Result<Handle, String> {
    // SAFETY: NULL names choose the current computer's active SCM database.
    let handle = unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    };
    if (handle as usize) == 0 {
        Err(err("OpenSCManagerW"))
    } else {
        Ok(Handle(handle))
    }
}

fn existing(manager: &Handle) -> Result<Option<Handle>, String> {
    let name = wide(crate::windows_service::NAME);
    // SAFETY: The service name is a fixed, NUL-terminated constant.
    let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_RIGHTS) };
    if (handle as usize) != 0 {
        return Ok(Some(Handle(handle)));
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_SERVICE_DOES_NOT_EXIST {
        Ok(None)
    } else {
        Err(format!("OpenServiceW failed (Windows error {code})"))
    }
}

fn config(service: &Handle) -> Result<(String, u32, u32), String> {
    let mut size = 0u32;
    // SAFETY: Standard two-call SCM buffer negotiation.
    unsafe { QueryServiceConfigW(service.0, null_mut(), 0, &mut size) };
    if size < size_of::<QUERY_SERVICE_CONFIGW>() as u32 || size > 65_536 {
        return Err("SCM configuration has an invalid bounded size".into());
    }
    // u64 backing ensures required structure alignment; valid for any x64
    // pointer fields within QUERY_SERVICE_CONFIGW.
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    let ok = unsafe {
        QueryServiceConfigW(
            service.0,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * 8) as u32,
            &mut size,
        )
    };
    if ok == 0 {
        return Err(err("QueryServiceConfigW"));
    }
    // SAFETY: QueryServiceConfigW populated the aligned structure and returns
    // a NUL-terminated lpBinaryPathName valid while buffer remains allocated.
    let record = unsafe { &*(buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>()) };
    if record.lpBinaryPathName.is_null() {
        return Err("SCM service has no binary path".into());
    }
    let mut count = 0usize;
    while count <= 2 * MAX_PATH_CHARS {
        // SAFETY: The OS-provided SCM string has NUL termination. Reject
        // implausibly long strings rather than accepting truncated commands.
        if unsafe { *record.lpBinaryPathName.add(count) } == 0 {
            break;
        }
        count += 1;
    }
    if count > 2 * MAX_PATH_CHARS {
        return Err("SCM binary command is oversized".into());
    }
    let command =
        String::from_utf16(unsafe { std::slice::from_raw_parts(record.lpBinaryPathName, count) })
            .map_err(|_| "SCM binary command is invalid UTF-16")?;
    Ok((command, record.dwStartType, record.dwServiceType))
}

fn require_owned(service: &Handle, expected: &str) -> Result<(), String> {
    let (actual, start, kind) = config(service)?;
    if actual != expected || start != SERVICE_DEMAND_START || kind != SERVICE_WIN32_OWN_PROCESS {
        return Err(
            "existing service is not the exact on-demand FlowBridge Rust candidate; no mutation"
                .into(),
        );
    }
    Ok(())
}

fn require_stopped(service: &Handle) -> Result<(), String> {
    let mut process: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut bytes = 0u32;
    // SAFETY: The destination has the expected SCM status structure layout.
    let ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut process as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes,
        )
    };
    if ok == 0 {
        return Err(err("QueryServiceStatusEx"));
    }
    if bytes != size_of::<SERVICE_STATUS_PROCESS>() as u32
        || process.dwCurrentState != SERVICE_STOPPED
    {
        return Err("SCM mutation requires a fully stopped service".into());
    }
    Ok(())
}

fn change_command(service: &Handle, command: &str) -> Result<(), String> {
    let value = wide(command);
    // SAFETY: Only the binary path and manual start type are changed.
    // All other fields are deliberately SERVICE_NO_CHANGE / NULL.
    let ok = unsafe {
        ChangeServiceConfigW(
            service.0,
            SERVICE_NO_CHANGE,
            SERVICE_DEMAND_START,
            SERVICE_NO_CHANGE,
            value.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
            null(),
        )
    };
    if ok == 0 {
        Err(err("ChangeServiceConfigW"))
    } else {
        Ok(())
    }
}

fn report(action: &str) -> Value {
    json!({
        "ok":true,
        "action":action,
        "scm_on_demand":true,
        "scm_service_started_by_command":false,
        "driver_installed":false,
        "driver_capture_active":false,
        "native_process_proof":false,
        "protected_redirect_available":false,
        "dns_leak_free":false,
        "win10_11_acceptance":false,
        "release_accepted":false
    })
}

/// Create only a new, manually started SCM record after strict profile
/// validation. An existing record is never adopted or overwritten.
pub fn stage(config_path: &str) -> Result<Value, String> {
    exact_path(config_path)?;
    crate::control_plane::validate_scm_profile(Path::new(config_path))?;
    let command = image_command(config_path)?;
    let scm = manager()?;
    if existing(&scm)?.is_some() {
        return Err("candidate service already exists; refusing overwrite".into());
    }
    let name = wide(crate::windows_service::NAME);
    let display = wide("FlowBridge Rust Explicit SOCKS Candidate (manual)");
    let binary = wide(&command);
    // SAFETY: All strings live through this synchronous SCM call; no service
    // start, recovery action, driver installation or automatic boot is enabled.
    let handle = unsafe {
        CreateServiceW(
            scm.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_RIGHTS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    if (handle as usize) == 0 {
        return Err(err("CreateServiceW"));
    }
    let service = Handle(handle);
    if let Err(error) = require_owned(&service, &command).and_then(|_| require_stopped(&service)) {
        // Roll back a newly created record; preserve a visible error if the
        // cleanup itself fails. Never return success on an unverified install.
        let undone = unsafe { DeleteService(service.0) } != 0;
        return Err(format!(
            "new service verification failed: {error}; rollback_deleted={undone}"
        ));
    }
    Ok(report("staged_manual_only"))
}

/// Change only the config path of an exactly owned, STOPPED service. A failed
/// postcondition rolls the SCM binary command back to the prior value.
pub fn replace(old_config: &str, new_config: &str) -> Result<Value, String> {
    let old = image_command(old_config)?;
    exact_path(new_config)?;
    crate::control_plane::validate_scm_profile(Path::new(new_config))?;
    let next = image_command(new_config)?;
    if next == old {
        return Err("replacement requires a different profile path".into());
    }
    let scm = manager()?;
    let service = existing(&scm)?.ok_or("candidate service not installed")?;
    require_owned(&service, &old)?;
    require_stopped(&service)?;
    change_command(&service, &next)?;
    if let Err(error) = require_owned(&service, &next).and_then(|_| require_stopped(&service)) {
        let rolled_back = change_command(&service, &old)
            .and_then(|_| require_owned(&service, &old))
            .is_ok();
        return Err(format!(
            "SCM replacement verification failed: {error}; rollback_restored={rolled_back}"
        ));
    }
    Ok(report("replaced_stopped_only"))
}

/// Remove only an exactly matching, STOPPED service record. A changed binary
/// path, different config path or running service is never deleted.
pub fn remove(config_path: &str) -> Result<Value, String> {
    let expected = image_command(config_path)?;
    let scm = manager()?;
    let service = existing(&scm)?.ok_or("candidate service not installed")?;
    require_owned(&service, &expected)?;
    require_stopped(&service)?;
    let ok = unsafe { DeleteService(service.0) };
    if ok == 0 {
        return Err(err("DeleteService"));
    }
    Ok(report("removed_stopped_only"))
}


const MAX_STAGED_BINARY_BYTES: u64 = 64 * 1024 * 1024;

/// Windows CNG SHA-256, not an ad-hoc hash and not an external executable.
/// A tightly bounded input is required so a command cannot exhaust the
/// privileged process with a multi-gigabyte staged image.
fn sha256_hex(bytes: &[u8]) -> Result<String, String> {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        #[link_name = "BCryptOpenAlgorithmProvider"]
        fn open_algorithm(
            result: *mut *mut c_void,
            algorithm: *const u16,
            implementation: *const u16,
            flags: u32,
        ) -> i32;
        #[link_name = "BCryptHash"]
        fn hash_one_shot(
            algorithm: *mut c_void,
            secret: *mut u8,
            secret_len: u32,
            input: *mut u8,
            input_len: u32,
            output: *mut u8,
            output_len: u32,
        ) -> i32;
        #[link_name = "BCryptCloseAlgorithmProvider"]
        fn close_algorithm(algorithm: *mut c_void, flags: u32) -> i32;
    }

    let mut provider = null_mut();
    let algorithm = wide("SHA256");
    // SAFETY: All pointers reference owned buffers and provider is closed
    // regardless of whether the bounded hash call succeeds.
    if unsafe { open_algorithm(&mut provider, algorithm.as_ptr(), null(), 0) } != 0
        || provider.is_null()
    {
        return Err("Windows CNG SHA-256 provider unavailable".into());
    }
    let mut digest = [0u8; 32];
    let status = unsafe {
        hash_one_shot(
            provider,
            null_mut(),
            0,
            bytes.as_ptr().cast_mut(),
            bytes.len() as u32,
            digest.as_mut_ptr(),
            digest.len() as u32,
        )
    };
    let close_status = unsafe { close_algorithm(provider, 0) };
    if status != 0 || close_status != 0 {
        return Err("Windows CNG SHA-256 failed".into());
    }
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn x64_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x100 || bytes.get(0..2) != Some(b"MZ".as_slice()) {
        return false;
    }
    let offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    offset.checked_add(26).is_some_and(|end| {
        end <= bytes.len()
            && bytes.get(offset..offset + 4) == Some(b"PE\0\0".as_slice())
            && bytes.get(offset + 4..offset + 6) == Some([0x64, 0x86].as_slice())
            && bytes.get(offset + 24..offset + 26) == Some([0x0b, 0x02].as_slice())
    })
}

/// Upgrade or roll back the executable AND profile of an exactly owned,
/// already-stopped on-demand Rust service. Nothing here installs a driver,
/// changes Windows security settings, starts a service, or enables capture.
///
/// The next executable must already exist alongside the current executable;
/// an exclusive-read file handle prevents writers/deleters during the SCM
/// transition. This is not a full installer/ACL/atomic on-disk replacement.
pub fn binary_replace(
    old_config: &str,
    next_executable: &str,
    next_config: &str,
    expected_sha256: &str,
) -> Result<Value, String> {
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;

    if expected_sha256.len() != 64
        || !expected_sha256.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("Expected SHA-256 must be exactly 64 hexadecimal characters".into());
    }
    exact_path(next_executable)?;
    exact_path(next_config)?;
    if !Path::new(next_executable)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
    {
        return Err("Staged Rust candidate must be an .exe file".into());
    }
    crate::control_plane::validate_scm_profile(Path::new(next_config))?;

    let current = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| "Current Rust agent executable cannot be resolved")?;
    let next = std::fs::canonicalize(next_executable)
        .map_err(|_| "Staged Rust executable cannot be resolved")?;
    let same_folder = current.parent().zip(next.parent()).is_some_and(|(a, b)| {
        a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
    });
    if !same_folder || current == next {
        return Err("Staged binary must be a distinct sibling of this Rust agent".into());
    }

    // FILE_SHARE_READ only: no simultaneous open-for-write or delete while
    // the hash and SCM command are verified. Held until the function exits.
    let mut staged = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x0000_0001)
        .open(&next)
        .map_err(|_| "Cannot exclusively validate the staged binary")?;
    let size = staged
        .metadata()
        .map_err(|_| "Cannot inspect staged executable metadata")?
        .len();
    if size < 256 || size > MAX_STAGED_BINARY_BYTES {
        return Err("Staged executable size outside allowed range".into());
    }
    let mut content = Vec::with_capacity(size as usize);
    (&mut staged)
        .take(MAX_STAGED_BINARY_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|_| "Cannot read staged executable")?;
    if content.len() as u64 != size || !x64_pe(&content) {
        return Err("Staged image is not a stable x64 PE32+ executable".into());
    }
    let observed_sha256 = sha256_hex(&content)?;
    if !observed_sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err("Staged executable SHA-256 mismatch; SCM unchanged".into());
    }

    let old_command = image_command(old_config)?;
    let next_command = format!("\"{next_executable}\" service-run \"{next_config}\"");
    if next_command == old_command {
        return Err("Binary upgrade cannot be a no-op".into());
    }
    let scm = manager()?;
    let service = existing(&scm)?.ok_or("Rust candidate service not installed")?;
    require_owned(&service, &old_command)?;
    require_stopped(&service)?;
    change_command(&service, &next_command)?;
    if let Err(error) =
        require_owned(&service, &next_command).and_then(|_| require_stopped(&service))
    {
        let rolled_back = change_command(&service, &old_command)
            .and_then(|_| require_owned(&service, &old_command))
            .and_then(|_| require_stopped(&service))
            .is_ok();
        return Err(format!(
            "Rust binary transition postcondition failed: {error}; rollback_restored={rolled_back}"
        ));
    }
    let mut response = report("binary_and_profile_replaced_stopped_only");
    response["staged_executable_sha256"] = json!(observed_sha256);
    response["staged_x64_pe_verified"] = json!(true);
    response["staged_file_locked_during_scm_transition"] = json!(true);
    response["on_disk_installer_or_acl_proof"] = json!(false);
    response["service_running_or_started"] = json!(false);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cng_hash_and_pe_rejection_are_independent() {
        assert_eq!(
            sha256_hex(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!x64_pe(b"MZ"));
        assert!(!x64_pe(&vec![0u8; 256]));
    }

    #[test]
    fn exact_quoted_path_only() {
        assert!(exact_path("relative.json").is_err());
        assert!(exact_path("C:\\bad\"-service").is_err());
        assert!(exact_path("C:\\bad\nservice").is_err());
        assert!(exact_path("C:\\safe\\config.json").is_ok());
    }
}
