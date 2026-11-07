//! Original Rust, read-only Windows Filtering Platform/BFE feasibility probe.
//!
//! This is explicitly NOT a WFP callout, filter installer or proof of NDISRD
//! packet attribution. It never installs/deletes/reorders rules. It cannot
//! establish which stack layer sees a selected application's packet or whether
//! a persistent rule remains effective after a protected agent crashes.
#![cfg(windows)]
use serde_json::{json, Value};
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0,
    FwpmFilterEnum0, FwpmFreeMemory0, FWPM_FILTER0, FWPM_FILTER_FLAG_BOOTTIME,
    FWPM_FILTER_FLAG_PERSISTENT,
};

const RPC_C_AUTHN_WINNT: u32 = 10;
const PAGE_SIZE: u32 = 128;
const MAX_PAGES: usize = 64;

struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: Only a successful FwpmEngineOpen0 handle is wrapped.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

struct Enumerator {
    engine: HANDLE,
    handle: HANDLE,
}
impl Drop for Enumerator {
    fn drop(&mut self) {
        // SAFETY: The owning BFE session remains live until this Drop finishes.
        unsafe { FwpmFilterDestroyEnumHandle0(self.engine, self.handle) };
    }
}

struct FilterPage(*mut *mut FWPM_FILTER0);
impl Drop for FilterPage {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut allocated = self.0.cast::<c_void>();
            // SAFETY: BFE allocated the array; free the returned array once.
            // FwpmFreeMemory0 also releases the nested filter objects.
            unsafe { FwpmFreeMemory0(&mut allocated) };
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    filters: u32,
    persistent: u32,
    boot_time: u32,
    complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Engine(u32),
    Enumerator(u32),
    Page(u32),
    InvalidPage,
}

fn read_filters() -> Result<Counts, Failure> {
    let mut raw_engine: HANDLE = null_mut();
    // SAFETY: Null server, identity, and session mean local read-only session;
    // the only engine/filter calls made below are open, enumerate and close.
    let status =
        unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), null(), &mut raw_engine) };
    if status != 0 {
        return Err(Failure::Engine(status));
    }
    if raw_engine.is_null() {
        return Err(Failure::InvalidPage);
    }
    let engine = Engine(raw_engine);

    let mut raw_enum: HANDLE = null_mut();
    // SAFETY: Null template enumerates accessible filters in a BFE snapshot.
    let status = unsafe { FwpmFilterCreateEnumHandle0(engine.0, null(), &mut raw_enum) };
    if status != 0 {
        return Err(Failure::Enumerator(status));
    }
    if raw_enum.is_null() {
        return Err(Failure::InvalidPage);
    }
    let enumeration = Enumerator {
        engine: engine.0,
        handle: raw_enum,
    };
    let mut totals = Counts::default();
    for _ in 0..MAX_PAGES {
        let mut raw_entries: *mut *mut FWPM_FILTER0 = null_mut();
        let mut entries_returned: u32 = 0;
        // SAFETY: BFE owns the returned bounded pointer array; FilterPage
        // frees it even when a validation or classification error occurs.
        let status = unsafe {
            FwpmFilterEnum0(
                engine.0,
                enumeration.handle,
                PAGE_SIZE,
                &mut raw_entries,
                &mut entries_returned,
            )
        };
        let page = FilterPage(raw_entries);
        if status != 0 {
            return Err(Failure::Page(status));
        }
        if entries_returned > PAGE_SIZE || (entries_returned != 0 && page.0.is_null()) {
            return Err(Failure::InvalidPage);
        }
        if entries_returned > 0 {
            // SAFETY: A successful enumeration supplies exactly this many
            // entries, each pointing to one BFE-owned FWPM_FILTER0.
            let filters = unsafe { std::slice::from_raw_parts(page.0, entries_returned as usize) };
            for &entry in filters {
                if entry.is_null() {
                    return Err(Failure::InvalidPage);
                }
                // SAFETY: FilterPage stays alive for the entire iteration.
                let flags = unsafe { (*entry).flags };
                totals.persistent += u32::from(flags & FWPM_FILTER_FLAG_PERSISTENT != 0);
                totals.boot_time += u32::from(flags & FWPM_FILTER_FLAG_BOOTTIME != 0);
            }
        }
        totals.filters += entries_returned;
        if entries_returned < PAGE_SIZE {
            totals.complete = true;
            break;
        }
    }
    Ok(totals)
}

fn classify(observed: Result<Counts, Failure>) -> Value {
    let mut result = json!({
        "kind": "original_rust_windows_wfp_readonly_filter_inventory",
        "ok": false,
        "read_only": true,
        "engine_opened": false,
        "enumeration_completed": false,
        "filter_sample_count": null,
        "persistent_sample_count": null,
        "boot_time_sample_count": null,
        "sample_complete": false,
        "max_sample": PAGE_SIZE as usize * MAX_PAGES,
        "error_stage": null,
        "win32_error": null,
        "filter_policy_modified": false,
        "driver_mode_modified": false,
        "native_packet_pid_bound": false,
        "arbitrary_selected_app_accepted": false,
        "crash_persistent_fail_closed": false,
        "wfp_ndisrd_ordering_proved": false,
        "dns_leak_free": false,
        "win10_11_acceptance": false,
        "release_accepted": false
    });
    match observed {
        Ok(counts) => {
            result["ok"] = json!(true);
            result["engine_opened"] = json!(true);
            result["enumeration_completed"] = json!(true);
            result["filter_sample_count"] = json!(counts.filters);
            result["persistent_sample_count"] = json!(counts.persistent);
            result["boot_time_sample_count"] = json!(counts.boot_time);
            result["sample_complete"] = json!(counts.complete);
        }
        Err(error) => {
            let (stage, code, engine_opened) = match error {
                Failure::Engine(code) => ("engine_open", Some(code), false),
                Failure::Enumerator(code) => ("enum_create", Some(code), true),
                Failure::Page(code) => ("enum_page", Some(code), true),
                Failure::InvalidPage => ("malformed_bfe_reply", None, false),
            };
            result["engine_opened"] = json!(engine_opened);
            result["error_stage"] = json!(stage);
            result["win32_error"] = json!(code);
        }
    }
    result
}

/// A real OS BFE query, with no names, provider GUIDs, process identity,
/// endpoints or packet payloads emitted. Filter presence is not enforcement.
pub fn report() -> Value {
    classify(read_filters())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_and_boot_time_counts_never_authorize_protected_routing() {
        let result = classify(Ok(Counts {
            filters: 22,
            persistent: 7,
            boot_time: 3,
            complete: true,
        }));
        assert_eq!(result["ok"], true);
        assert_eq!(result["persistent_sample_count"], 7);
        assert_eq!(result["boot_time_sample_count"], 3);
        for field in [
            "filter_policy_modified",
            "native_packet_pid_bound",
            "arbitrary_selected_app_accepted",
            "crash_persistent_fail_closed",
            "wfp_ndisrd_ordering_proved",
            "dns_leak_free",
            "win10_11_acceptance",
            "release_accepted",
        ] {
            assert_eq!(result[field], false, "{field}");
        }
    }

    #[test]
    fn access_denied_and_incomplete_inventory_are_never_reported_as_acceptance() {
        let denied = classify(Err(Failure::Enumerator(5)));
        assert_eq!(denied["ok"], false);
        assert_eq!(denied["engine_opened"], true);
        assert_eq!(denied["error_stage"], "enum_create");
        assert_eq!(denied["win32_error"], 5);
        assert!(denied["filter_sample_count"].is_null());
        let truncated = classify(Ok(Counts {
            filters: 8192,
            persistent: 11,
            boot_time: 0,
            complete: false,
        }));
        assert_eq!(truncated["sample_complete"], false);
        assert_eq!(truncated["crash_persistent_fail_closed"], false);
    }
}
