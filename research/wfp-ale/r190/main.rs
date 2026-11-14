//! R190: R188 AppId gate plus read-only same-sublayer competition and weight diagnostics. NOT WFP proof.
//! No install/remove/reconfigure/network-socket operations exist in this binary.
#[cfg(not(windows))]
fn main() {
    eprintln!("UNSUPPORTED: this read-only diagnostic requires Windows");
    std::process::exit(2);
}
#[cfg(windows)]
mod windows_probe {
    use std::{ffi::{c_void, OsStr}, os::windows::ffi::OsStrExt, ptr, slice};
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
    struct FilterEnumHandle { engine: HANDLE, handle: HANDLE }
    impl Drop for FilterEnumHandle {
        fn drop(&mut self) {
            if !self.handle.is_null() { unsafe { FwpmFilterDestroyEnumHandle0(self.engine, self.handle); } }
        }
    }
    // Conservative admission: any *visible* non-R19 filter in the same sublayer
    // and on one of our four layers makes the inventory non-attestable. A missing
    // foreign filter does NOT establish global exclusivity (BFE ACL visibility).
    unsafe fn inspect_visible_competitors(engine: HANDLE) -> Result<u64, String> {
        let mut cursor = FilterEnumHandle { engine, handle: ptr::null_mut() };
        check(FwpmFilterCreateEnumHandle0(engine, ptr::null(), &mut cursor.handle),
              "filter_enum_create")?;
        require(!cursor.handle.is_null(), "null_filter_enum")?;
        let mut total = 0u64;
        for _page in 0..512 {  // Fail unknown beyond 32768 entries, not partial success.
            let mut raw: *mut *mut FWPM_FILTER0 = ptr::null_mut();
            let mut count = 0u32;
            let status = FwpmFilterEnum0(engine, cursor.handle, 64, &mut raw, &mut count);
            let owned = Mem(raw); // FwpmFilterEnum0: free array, not entries individually.
            check(status, "filter_enum_page")?;
            require(count <= 64 && (count == 0 || !owned.0.is_null()),
                    "invalid_filter_page")?;
            total = total.checked_add(count as u64).ok_or("UNKNOWN: filter count overflow")?;
            if count != 0 {
                for entry in slice::from_raw_parts(owned.0, count as usize) {
                    require(!(*entry).is_null(), "null_filter_entry")?;
                    let f = &**entry;
                    let relevant_layer = LAYERS.iter().any(|layer| equal(f.layerKey, *layer));
                    let ours = (0..4).any(|i| equal(f.filterKey, filter_key(i)));
                    require(!(equal(f.subLayerKey, SUB) && relevant_layer && !ours),
                            "visible_foreign_filter_in_r19_sublayer")?;
                }
            }
            if count < 64 { return Ok(total); }
        }
        Err("UNKNOWN: filter enumeration exceeded bounded 32768 entries".into())
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
    // WFP AppId for the supplied selected EXE path, not a PID/kernel identity.
    fn selected_appid(path: &OsStr) -> Result<Vec<u8>, String> {
        let mut wide: Vec<u16> = path.encode_wide().collect();
        require(wide.len() >= 4 && (((b'A' as u16)..=(b'Z' as u16)).contains(&wide[0]) ||
              ((b'a' as u16)..=(b'z' as u16)).contains(&wide[0]))
            && wide[1] == b':' as u16 && wide[2] == b'\\' as u16
            && !wide.contains(&0), "local_absolute_drive_path_required")?;
        wide.push(0);
        let mut raw: *mut FWP_BYTE_BLOB = ptr::null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut raw) };
        let owned = Mem(raw);
        check(status, "selected_appid_from_filename")?;
        require(!owned.0.is_null(), "null_selected_appid")?;
        let blob = unsafe { &*owned.0 };
        require(blob.size >= 4 && blob.size <= 514 && blob.size % 2 == 0
            && !blob.data.is_null(), "selected_appid_blob_shape")?;
        let bytes = unsafe { slice::from_raw_parts(blob.data, blob.size as usize) };
        require(bytes.ends_with(&[0, 0]) &&
            !bytes[..bytes.len()-2].chunks_exact(2).any(|ch| ch == [0, 0]),
            "selected_appid_utf16_terminator")?;
        Ok(bytes.to_vec())
    }
    unsafe fn inspect(engine: HANDLE, selected: &[u8]) -> Result<u64, String> {
        let sessions = session_count(engine)?;
        // Both enumeration and GetByKey occur inside a single read-only BFE
        // transaction; this does not attest runtime classify callbacks.
        let _visible_filters = inspect_visible_competitors(engine)?;
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
                && f.weight.r#type == FWP_EMPTY
                && f.effectiveWeight.r#type == FWP_UINT64
                && f.filterId != 0
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
                && (*blob).size as usize == selected.len(), "appid_blob_size_mismatch")?;
            let actual = slice::from_raw_parts((*blob).data, selected.len());
            require(actual == selected, "selected_appid_bytes_mismatch")?;
            // Exact BFE condition bytes are not a PID/creation-epoch/kernel-origin join.
        }
        Ok(sessions)
    }
    fn run(selected_exe: &OsStr) -> Result<u64, String> {
        // Do not treat filename-derived AppId as canonical process identity.
        let selected = selected_appid(selected_exe)?;
        let mut h: HANDLE = ptr::null_mut();
        let code = unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut h) };
        check(code, "engine_open")?;
        let engine = Engine(h);
        require(!engine.0.is_null(), "null_engine")?;
        // Explicit management-object read-only transaction; not an enforcement fence.
        check(unsafe { FwpmTransactionBegin0(engine.0, FWPM_TXN_READ_ONLY) }, "readonly_txn_begin")?;
        let data = unsafe { inspect(engine.0, &selected) };
        match data {
            Ok(sessions) => {
                check(unsafe { FwpmTransactionCommit0(engine.0) }, "readonly_txn_commit")?;
                Ok(sessions)
            }
            Err(e) => { unsafe { FwpmTransactionAbort0(engine.0); } Err(e) }
        }
    }
    pub fn main() {
        let mut args = std::env::args_os().skip(1);
        let path = match (args.next(), args.next()) {
            (Some(p), None) => p,
            _ => { eprintln!("usage: flowbridge-r190-bfe-readonly <local-drive-selected-exe>");
                   std::process::exit(2); }
        };
        match run(path.as_os_str()) {
            Ok(sessions) => {
                println!("{{\"state\":\"STRUCTURE_OBSERVED_NOT_PROOF\",\"filters\":4,\"callouts\":4,\"sublayers\":1,\"sessions_visible\":{sessions},\"kernel_identity\":\"UNKNOWN\",\"enforcement\":\"UNKNOWN\",\"continuity\":\"UNKNOWN\"}}");
            }
            Err(error) => { eprintln!("{error}"); std::process::exit(3); }
        }
    }
}
#[cfg(windows)]
fn main() { windows_probe::main(); }
