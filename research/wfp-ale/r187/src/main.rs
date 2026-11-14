//! R187: Windows-only, no-driver, read-only inventory. NOT proof of WFP enforcement.
//! No install/remove/reconfigure/network-socket operations exist in this binary.
#[cfg(not(windows))]
fn main() {
    eprintln!("UNSUPPORTED: this read-only diagnostic requires Windows");
    std::process::exit(2);
}
#[cfg(windows)]
mod windows_probe {
    use std::{ffi::c_void, ptr, slice};
    use windows_sys::{
        core::GUID,
        Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
    };

    const SUB: GUID = GUID::from_u128(0x1649f024_25b3_4e01_9ca1_5ca803010019);
    const CALLOUTS: [u128; 4] = [
        0x1649f018_25b3_4e01_9ca1_5ca803010019, // AUTH v4
        0x1649f019_25b3_4e01_9ca1_5ca803010019, // AUTH v6
        0x1649f014_25b3_4e01_9ca1_5ca803010019, // REDIRECT v4
        0x1649f016_25b3_4e01_9ca1_5ca803010019, // REDIRECT v6
    ];
    const LAYERS: [GUID; 4] = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
    ];
    fn equal(a: GUID, b: GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }
    fn filter_key(n: usize) -> GUID {
        GUID::from_u128(0x1649f030_25b3_4e01_9ca1_5ca803010019 + ((n as u128) << 96))
    }
    fn fail(stage: &str, code: u32) -> String {
        format!("UNKNOWN at {stage}: BFE code 0x{code:08x}; never infer ABSENT or enforcement")
    }
    fn require(ok: bool, stage: &str) -> Result<(), String> {
        if ok { Ok(()) } else { Err(format!("NO_ATTESTATION: {stage}")) }
    }
    fn check(code: u32, stage: &str) -> Result<(), String> {
        if code == 0 { Ok(()) } else { Err(fail(stage, code)) }
    }
    struct Engine(HANDLE);
    impl Drop for Engine {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { FwpmEngineClose0(self.0); } }
        }
    }
    struct Mem<T>(*mut T);
    impl<T> Drop for Mem<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let mut p = self.0.cast::<c_void>();
                    FwpmFreeMemory0(&mut p);
                }
            }
        }
    }
    struct EnumHandle { engine: HANDLE, handle: HANDLE }
    impl Drop for EnumHandle {
        fn drop(&mut self) {
            if !self.handle.is_null() { unsafe { FwpmSessionDestroyEnumHandle0(self.engine, self.handle); } }
        }
    }
    unsafe fn session_count(engine: HANDLE) -> Result<u64, String> {
        let mut cursor = EnumHandle { engine, handle: ptr::null_mut() };
        check(FwpmSessionCreateEnumHandle0(engine, ptr::null(), &mut cursor.handle), "session_enum_create")?;
        require(!cursor.handle.is_null(), "null_session_enum")?;
        let mut total = 0u64;
        loop {
            let mut arr: *mut *mut FWPM_SESSION0 = ptr::null_mut();
            let mut count = 0u32;
            let status = FwpmSessionEnum0(engine, cursor.handle, 64, &mut arr, &mut count);
            let memory = Mem(arr);
            check(status, "session_enum_page")?;
            require(count <= 64 && (count == 0 || !memory.0.is_null()), "invalid_session_page")?;
            total = total.checked_add(count as u64).ok_or("UNKNOWN: session count overflow")?;
            if count < 64 { break; }
        }
        Ok(total) // Snapshot, NOT ownership relation to filter keys.
    }
    unsafe fn inspect(engine: HANDLE) -> Result<u64, String> {
        let sessions = session_count(engine)?;
        let mut sub: *mut FWPM_SUBLAYER0 = ptr::null_mut();
        let code = FwpmSubLayerGetByKey0(engine, &SUB, &mut sub);
        let owned = Mem(sub);
        check(code, "sublayer_get_by_key")?;
        require(!owned.0.is_null(), "null_sublayer")?;
        require(equal((*owned.0).subLayerKey, SUB) && (*owned.0).weight == 0x7000,
                "unexpected_sublayer")?;
        for i in 0..4 {
            let key = GUID::from_u128(CALLOUTS[i]);
            let mut c: *mut FWPM_CALLOUT0 = ptr::null_mut();
            let status = FwpmCalloutGetByKey0(engine, &key, &mut c);
            let callout = Mem(c);
            check(status, "callout_get_by_key")?;
            require(!callout.0.is_null(), "null_callout")?;
            require(equal((*callout.0).calloutKey, key)
                && equal((*callout.0).applicableLayer, LAYERS[i])
                && ((*callout.0).flags & FWPM_CALLOUT_FLAG_REGISTERED) != 0,
                "callout_unregistered_or_wrong_layer")?;
            let fk = filter_key(i);
            let mut f: *mut FWPM_FILTER0 = ptr::null_mut();
            let status = FwpmFilterGetByKey0(engine, &fk, &mut f);
            let filter = Mem(f);
            check(status, "filter_get_by_key")?;
            require(!filter.0.is_null(), "null_filter")?;
            let f = &*filter.0;
            let action = if i < 2 { FWP_ACTION_CALLOUT_TERMINATING } else { FWP_ACTION_CALLOUT_UNKNOWN };
            require(equal(f.filterKey, fk) && equal(f.subLayerKey, SUB)
                && equal(f.layerKey, LAYERS[i]) && f.flags == 0
                && f.action.r#type == action
                && equal(f.action.Anonymous.calloutKey, key)
                && f.numFilterConditions == 2 && !f.filterCondition.is_null(),
                "unexpected_filter_scope_or_action")?;
            let cond = slice::from_raw_parts(f.filterCondition, 2);
            let app_key = if i < 2 { FWPM_CONDITION_ALE_ORIGINAL_APP_ID } else { FWPM_CONDITION_ALE_APP_ID };
            let app = cond.iter().find(|x| equal(x.fieldKey, app_key))
                .ok_or("NO_ATTESTATION: missing_appid_condition")?;
            let proto = cond.iter().find(|x| equal(x.fieldKey, FWPM_CONDITION_IP_PROTOCOL))
                .ok_or("NO_ATTESTATION: missing_tcp_condition")?;
            require(app.matchType == FWP_MATCH_EQUAL && app.conditionValue.r#type == FWP_BYTE_BLOB_TYPE
                && proto.matchType == FWP_MATCH_EQUAL && proto.conditionValue.r#type == FWP_UINT8
                && proto.conditionValue.Anonymous.uint8 == 6, "unexpected_filter_conditions")?;
            let blob = app.conditionValue.Anonymous.byteBlob;
            require(!blob.is_null() && !(*blob).data.is_null()
                && (*blob).size >= 4 && (*blob).size <= 514 && (*blob).size % 2 == 0,
                "appid_blob_unavailable")?;
            // No inferred canonical EXE: this snapshot cannot join to PID/epoch.
        }
        Ok(sessions)
    }
    fn run() -> Result<u64, String> {
        let mut h: HANDLE = ptr::null_mut();
        let code = unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut h) };
        check(code, "engine_open")?;
        let engine = Engine(h);
        require(!engine.0.is_null(), "null_engine")?;
        // Explicit management-object read-only transaction; not an enforcement fence.
        check(unsafe { FwpmTransactionBegin0(engine.0, FWPM_TXN_READ_ONLY) }, "readonly_txn_begin")?;
        let data = unsafe { inspect(engine.0) };
        match data {
            Ok(sessions) => {
                check(unsafe { FwpmTransactionCommit0(engine.0) }, "readonly_txn_commit")?;
                Ok(sessions)
            }
            Err(e) => { unsafe { FwpmTransactionAbort0(engine.0); } Err(e) }
        }
    }
    pub fn main() {
        match run() {
            Ok(sessions) => {
                println!("{{\"state\":\"STRUCTURE_OBSERVED_NOT_PROOF\",\"filters\":4,\"callouts\":4,\"sublayers\":1,\"sessions_visible\":{sessions},\"kernel_identity\":\"UNKNOWN\",\"enforcement\":\"UNKNOWN\",\"continuity\":\"UNKNOWN\"}}");
            }
            Err(error) => { eprintln!("{error}"); std::process::exit(3); }
        }
    }
}
#[cfg(windows)]
fn main() { windows_probe::main(); }
