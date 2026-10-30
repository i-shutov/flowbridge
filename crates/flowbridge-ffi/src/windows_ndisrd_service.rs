//! Read-only SCM observation of the separately installed NDISRD driver service.
//!
//! A service entry or SERVICE_RUNNING does not prove driver provenance, NDIS
//! adapter binding, packet interception, Microsoft signature, or safe routing.
//! This code requests only SC_MANAGER_CONNECT and SERVICE_QUERY_STATUS.

#![cfg(windows)]

use serde_json::{json, Value};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
    SC_MANAGER_CONNECT, SERVICE_CONTINUE_PENDING, SERVICE_KERNEL_DRIVER, SERVICE_PAUSED,
    SERVICE_PAUSE_PENDING, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

const SERVICE_NAME: &str = "NDISRD";
// Win32 ERROR_SERVICE_DOES_NOT_EXIST. Permission errors must never be
// reported as an absent service (or treated as driver approval).
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;

struct OwnedServiceHandle(SC_HANDLE);

impl Drop for OwnedServiceHandle {
    fn drop(&mut self) {
        // SAFETY: Only handles successfully opened by the SCM APIs are wrapped.
        unsafe { CloseServiceHandle(self.0) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedService {
    service_type: u32,
    state: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryFailure {
    ScmOpen(u32),
    NotInstalled,
    ServiceOpen(u32),
    Status(u32),
}

fn service_state(state: u32) -> &'static str {
    match state {
        SERVICE_STOPPED => "stopped",
        SERVICE_START_PENDING => "start_pending",
        SERVICE_STOP_PENDING => "stop_pending",
        SERVICE_RUNNING => "running",
        SERVICE_CONTINUE_PENDING => "continue_pending",
        SERVICE_PAUSE_PENDING => "pause_pending",
        SERVICE_PAUSED => "paused",
        _ => "unknown",
    }
}

fn query() -> Result<ObservedService, QueryFailure> {
    // SAFETY: Null machine/database select the local active SCM database.
    // SC_MANAGER_CONNECT does not authorize service creation or mutation.
    let raw_scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if raw_scm.is_null() {
        return Err(QueryFailure::ScmOpen(unsafe { GetLastError() }));
    }
    let scm = OwnedServiceHandle(raw_scm);

    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    // SAFETY: name is NUL-terminated, the SCM handle is live. Query-only.
    let raw_service = unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if raw_service.is_null() {
        let error = unsafe { GetLastError() };
        return if error == ERROR_SERVICE_DOES_NOT_EXIST {
            Err(QueryFailure::NotInstalled)
        } else {
            Err(QueryFailure::ServiceOpen(error))
        };
    }
    let service = OwnedServiceHandle(raw_service);

    let mut status = SERVICE_STATUS::default();
    // SAFETY: The service handle is live and status is valid writable storage.
    // QueryServiceStatus never starts, stops, reconfigures or installs a driver.
    if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
        return Err(QueryFailure::Status(unsafe { GetLastError() }));
    }
    Ok(ObservedService {
        service_type: status.dwServiceType,
        state: status.dwCurrentState,
    })
}

fn classify(result: Result<ObservedService, QueryFailure>) -> Value {
    // Null is UNKNOWN, not false. The driver may be present but inaccessible.
    let mut report = json!({
        "service_name": SERVICE_NAME,
        "read_only": true,
        "service_registered": null,
        "kernel_driver_type": null,
        "service_state": "unknown",
        "service_error": null,
        "win32_error": null,
        "driver_signing_verified": false,
        "adapter_binding_verified": false,
        "capture_authorized": false
    });
    match result {
        Ok(observed) => {
            report["service_registered"] = json!(true);
            report["kernel_driver_type"] =
                json!((observed.service_type & SERVICE_KERNEL_DRIVER) != 0);
            report["service_state"] = json!(service_state(observed.state));
        }
        Err(QueryFailure::NotInstalled) => {
            report["service_registered"] = json!(false);
            report["service_error"] = json!("service_not_installed");
        }
        Err(QueryFailure::ScmOpen(error)) => {
            report["service_error"] = json!("scm_open_failed");
            report["win32_error"] = json!(error);
        }
        Err(QueryFailure::ServiceOpen(error)) => {
            report["service_error"] = json!("service_open_failed");
            report["win32_error"] = json!(error);
        }
        Err(QueryFailure::Status(error)) => {
            report["service_registered"] = json!(true);
            report["service_error"] = json!("service_status_query_failed");
            report["win32_error"] = json!(error);
        }
    }
    report
}

/// An independent diagnostic. Even an installed, running driver service
/// cannot authorize capture. Packet routing requires separate native proof.
pub(super) fn report() -> Value {
    classify(query())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_registration_is_not_capture_or_signature_evidence() {
        let value = classify(Ok(ObservedService {
            service_type: SERVICE_KERNEL_DRIVER,
            state: SERVICE_RUNNING,
        }));
        assert_eq!(value["service_registered"], true);
        assert_eq!(value["kernel_driver_type"], true);
        assert_eq!(value["service_state"], "running");
        assert_eq!(value["read_only"], true);
        assert_eq!(value["driver_signing_verified"], false);
        assert_eq!(value["adapter_binding_verified"], false);
        assert_eq!(value["capture_authorized"], false);
    }

    #[test]
    fn errors_are_unknown_except_confirmed_missing_service() {
        let missing = classify(Err(QueryFailure::NotInstalled));
        assert_eq!(missing["service_registered"], false);
        assert_eq!(missing["service_error"], "service_not_installed");

        for failure in [
            QueryFailure::ScmOpen(5),
            QueryFailure::ServiceOpen(5),
        ] {
            let blocked = classify(Err(failure));
            assert!(blocked["service_registered"].is_null());
            assert_eq!(blocked["win32_error"], 5);
            assert_eq!(blocked["capture_authorized"], false);
        }
        let status = classify(Err(QueryFailure::Status(87)));
        assert_eq!(status["service_registered"], true);
        assert!(status["kernel_driver_type"].is_null());
        assert_eq!(status["win32_error"], 87);
    }

    #[test]
    fn non_kernel_or_pending_service_is_not_a_usable_driver() {
        let wrong_type = classify(Ok(ObservedService {
            service_type: 0x10, // SERVICE_WIN32_OWN_PROCESS
            state: SERVICE_RUNNING,
        }));
        assert_eq!(wrong_type["kernel_driver_type"], false);
        assert_eq!(wrong_type["capture_authorized"], false);

        let pending = classify(Ok(ObservedService {
            service_type: SERVICE_KERNEL_DRIVER,
            state: SERVICE_START_PENDING,
        }));
        assert_eq!(pending["service_state"], "start_pending");
        assert_eq!(pending["capture_authorized"], false);
        assert_eq!(service_state(u32::MAX), "unknown");
    }

    #[test]
    fn local_observation_never_starts_service() {
        let observed = report();
        assert_eq!(observed["service_name"], SERVICE_NAME);
        assert_eq!(observed["read_only"], true);
        assert_eq!(observed["driver_signing_verified"], false);
        assert_eq!(observed["capture_authorized"], false);
    }
}
