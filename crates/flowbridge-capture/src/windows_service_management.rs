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
    OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_CHANGE_CONFIG,
    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
    QUERY_SERVICE_CONFIGW,
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
    format!("{action} failed (Windows error {})", unsafe { GetLastError() })
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
    let image = exe.to_str().ok_or("current executable path is not Unicode")?;
    exact_path(image)?;
    if !exe.is_file() {
        return Err("current executable does not exist".into());
    }
    Ok(format!("\"{image}\" service-run \"{config}\""))
}

fn manager() -> Result<Handle, String> {
    // SAFETY: NULL names choose the current computer's active SCM database.
    let handle = unsafe {
        OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)
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
    let command = String::from_utf16(
        unsafe { std::slice::from_raw_parts(record.lpBinaryPathName, count) },
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_quoted_path_only() {
        assert!(exact_path("relative.json").is_err());
        assert!(exact_path("C:\\bad\"-service").is_err());
        assert!(exact_path("C:\\bad\nservice").is_err());
        assert!(exact_path("C:\\safe\\config.json").is_ok());
    }
}
