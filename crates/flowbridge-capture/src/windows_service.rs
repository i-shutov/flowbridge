//! Windows SCM lifecycle for the explicitly configured Rust SOCKS candidate.
//! This does not install a service, activate NDISRD or provide protected routing.
//! Only a manually installed, on-demand SCM service may enter this mode.
#![cfg(windows)]

use serde_json::{json, Value};
use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

pub(crate) const NAME: &str = "FlowBridgeRustCandidateCI";
static CONFIG: OnceLock<PathBuf> = OnceLock::new();
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
// A successful dispatcher return does not prove that ServiceMain succeeded.
// Preserve the actual SCM lifecycle verdict for the agent process exit code.
static SERVICE_RESULT: AtomicU32 = AtomicU32::new(0);

pub(crate) fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::Acquire)
}

// SCM calls this on another system thread. Never stop the engine or touch a
// driver in this callback: request graceful shutdown in the service loop.
unsafe extern "system" fn control_handler(
    code: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        STOP_REQUESTED.store(true, Ordering::Release);
    }
    0
}

fn status(state: u32, accepts: u32, win32_error: u32, checkpoint: u32) -> SERVICE_STATUS {
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepts,
        dwWin32ExitCode: win32_error,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            15_000
        } else {
            0
        },
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let mut wide: Vec<u16> = NAME.encode_utf16().chain(Some(0)).collect();
    // SAFETY: SCM supplies ServiceMain. Its handler receives only stop/shutdown
    // controls, never untrusted user buffers or a driver handle.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(wide.as_mut_ptr(), Some(control_handler), null_mut())
    };
    if (handle as usize) == 0 {
        SERVICE_RESULT.store(unsafe { GetLastError() }.max(1), Ordering::Release);
        return;
    }
    STOP_REQUESTED.store(false, Ordering::Release);
    let _ = SERVICE_HANDLE.set(handle as usize);
    // SAFETY: A live SCM status handle is returned from registration.
    if unsafe { SetServiceStatus(handle, &status(SERVICE_START_PENDING, 0, 0, 1)) } == 0 {
        SERVICE_RESULT.store(unsafe { GetLastError() }.max(1), Ordering::Release);
        return;
    }
    let path = CONFIG
        .get()
        .expect("SCM service config must be set before dispatch");
    // Do not claim RUNNING before config and the real SOCKS engine have started.
    // The pipe and engine share the same controller; a failed pipe fails the
    // service rather than leaving an unmanageable background proxy.
    let result = std::panic::catch_unwind(|| crate::control_plane::serve_scm(path));
    let error = match result {
        Ok(Ok(_)) => 0,
        _ => 1067, // ERROR_PROCESS_ABORTED; never claim clean SCM shutdown.
    };
    // Report failure both to SCM and to the agent exit status. A clean
    // dispatcher return must not hide an abort during startup or shutdown.
    let reported = unsafe { SetServiceStatus(handle, &status(SERVICE_STOPPED, 0, error, 0)) };
    let final_error = if reported == 0 {
        unsafe { GetLastError() }.max(1)
    } else {
        error
    };
    SERVICE_RESULT.store(final_error, Ordering::Release);
}

pub(crate) fn mark_stopping() -> Result<(), String> {
    let handle = SERVICE_HANDLE
        .get()
        .copied()
        .ok_or("SCM service handler was not registered")?;
    // SAFETY: SCM control has requested a stop, and the registered status
    // handle remains valid until ServiceMain reports STOPPED.
    let ok = unsafe { SetServiceStatus(handle as _, &status(SERVICE_STOP_PENDING, 0, 0, 1)) };
    if ok == 0 {
        return Err(format!("SCM STOP_PENDING status failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(())
}

// Executed only after Controller has opened an engine AND the secure first
// named-pipe instance is bound, before the control pipe's accept loop. An
// unmanageable service must never advertise RUNNING to SCM. There is no
// driver or protected-allow side effect.
pub(crate) fn mark_running() -> Result<(), String> {
    // ServiceMain sets the global status handle via the SCM registration,
    // below. No caller outside SCM may report a service running.
    let handle = SERVICE_HANDLE
        .get()
        .copied()
        .ok_or("SCM service handler was not registered")?;
    // SAFETY: Handler is registered before entering the SCM controller.
    let ok = unsafe {
        SetServiceStatus(
            handle as _,
            &status(
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                0,
                0,
            ),
        )
    };
    if ok == 0 {
        return Err(format!("SCM RUNNING status failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(())
}
static SERVICE_HANDLE: OnceLock<usize> = OnceLock::new();

pub fn run(path: &str) -> Result<Value, String> {
    crate::windows_service_management::validate_local_file(path)?;
    SERVICE_RESULT.store(0, Ordering::Release);
    CONFIG
        .set(PathBuf::from(path))
        .map_err(|_| "SCM config already initialized")?;
    let mut name: Vec<u16> = NAME.encode_utf16().chain(Some(0)).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: table and its string live until the dispatcher returns, and
    // the service callbacks are ABI-conformant extern "system" functions.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        return Err(format!("SCM dispatcher unavailable: {}", unsafe {
            GetLastError()
        }));
    }
    let error = SERVICE_RESULT.load(Ordering::Acquire);
    if error != 0 {
        return Err(format!(
            "SCM service session failed (Windows error {error})"
        ));
    }
    Ok(json!({
        "ok":true, "scm_dispatch_completed":true,
        "driver_capture_active":false, "protected_redirect_available":false,
        "dns_leak_free":false, "release_accepted":false
    }))
}
