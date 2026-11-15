//! R199: read-only, non-atomic BFE baseline for a CLEAN host with no R19 dynamic session.
//! Never claims native ALE classification, provider provenance, enforcement or leak freedom.
#[cfg(not(windows))]
fn main() {
    eprintln!("UNSUPPORTED: Windows-only BFE management APIs");
    std::process::exit(2);
}
#[cfg(windows)]
mod probe {
    use std::{ffi::c_void, ptr};
    use windows_sys::{
        core::GUID,
        Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
    };

    const SUBLAYER: GUID = GUID::from_u128(0x1649f024_25b3_4e01_9ca1_5ca803010019);
    // Same ordering as kernel-r19/policy_plan.rs RULES: AUTH4, AUTH6, REDIRECT4, REDIRECT6.
    const CALLOUTS: [u128; 4] = [
        0x1649f018_25b3_4e01_9ca1_5ca803010019,
        0x1649f019_25b3_4e01_9ca1_5ca803010019,
        0x1649f014_25b3_4e01_9ca1_5ca803010019,
        0x1649f016_25b3_4e01_9ca1_5ca803010019,
    ];
    fn filter_key(i: usize) -> GUID {
        GUID::from_u128(0x1649f030_25b3_4e01_9ca1_5ca803010019 + ((i as u128) << 96))
    }
    struct Engine(HANDLE);
    impl Drop for Engine {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { FwpmEngineClose0(self.0); } }
        }
    }
    struct Owned<T>(*mut T);
    impl<T> Drop for Owned<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let mut opaque = self.0.cast::<c_void>();
                    FwpmFreeMemory0(&mut opaque);
                }
            }
        }
    }
    #[derive(Clone, Copy)]
    struct Readback { code: u32, visible: bool, registered: bool }
    impl Readback {
        fn json(self) -> String {
            format!("{{\"api_code\":{},\"visible\":{},\"registered\":{}}}",
                    self.code, self.visible, self.registered)
        }
    }
    fn sublayer(engine: HANDLE) -> Readback {
        let mut ptr = ptr::null_mut();
        let code = unsafe { FwpmSubLayerGetByKey0(engine, &SUBLAYER, &mut ptr) };
        let owned: Owned<FWPM_SUBLAYER0> = Owned(ptr);
        Readback { code, visible: code == 0 && !owned.0.is_null(), registered: false }
    }
    fn callout(engine: HANDLE, key: GUID) -> Readback {
        let mut ptr = ptr::null_mut();
        let code = unsafe { FwpmCalloutGetByKey0(engine, &key, &mut ptr) };
        let owned: Owned<FWPM_CALLOUT0> = Owned(ptr);
        let visible = code == 0 && !owned.0.is_null();
        let registered = visible && unsafe { (*owned.0).flags & FWPM_CALLOUT_FLAG_REGISTERED != 0 };
        Readback { code, visible, registered }
    }
    fn filter(engine: HANDLE, key: GUID) -> Readback {
        let mut ptr = ptr::null_mut();
        let code = unsafe { FwpmFilterGetByKey0(engine, &key, &mut ptr) };
        let owned: Owned<FWPM_FILTER0> = Owned(ptr);
        Readback { code, visible: code == 0 && !owned.0.is_null(), registered: false }
    }
    pub fn main() {
        if std::env::args_os().len() != 1 {
            eprintln!("usage: flowbridge-r199-clean-bfe-readonly (no arguments)");
            std::process::exit(2);
        }
        let mut handle: HANDLE = ptr::null_mut();
        let open = unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut handle) };
        if open != 0 || handle.is_null() {
            if !handle.is_null() { unsafe { FwpmEngineClose0(handle); } }
            println!("{{\"state\":\"UNKNOWN\",\"engine_api_code\":{},\"atomic\":false,\"kernel_proof\":false}}", open);
            std::process::exit(3);
        }
        let engine = Engine(handle);
        // Intentionally NO transaction: useful even without BEGIN_READ_TXN ACL.
        // This is NOT an atomic view; management objects can disappear between calls.
        let s = sublayer(engine.0);
        let mut calls = Vec::with_capacity(4);
        let mut filters = Vec::with_capacity(4);
        for (i, key) in CALLOUTS.iter().enumerate() {
            calls.push(callout(engine.0, GUID::from_u128(*key)).json());
            filters.push(filter(engine.0, filter_key(i)).json());
        }
        println!("{{\"state\":\"MANAGEMENT_READBACK_NOT_PROOF\",\"engine_api_code\":0,\"atomic\":false,\"kernel_proof\":false,\"sublayer\":{},\"callouts\":[{}],\"filters\":[{}]}}",
                 s.json(), calls.join(","), filters.join(","));
    }
}
#[cfg(windows)]
fn main() { probe::main(); }
