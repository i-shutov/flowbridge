//! GitHub-HOSTED Windows only: crash-persistent AppId-wide IPv4+IPv6 deny canary.
//! Independent SYSTEM rescue must be armed before any BFE mutation.
//! Not FlowBridge protected mode, not native NDISRD packet ownership or DNS leak proof.
#![cfg(windows)]
use crate::windows_wfp_dynamic_lab::{canonical_file_handle_paths, lookup_app};
use serde_json::{json, Value};
use std::{
    ffi::c_void,
    io::Write,
    path::Path,
    ptr::{null, null_mut},
    thread,
    time::Duration,
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
            FwpmFilterGetByKey0, FwpmFreeMemory0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
            FwpmSubLayerGetByKey0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
            FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
            FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT16,
            FWP_UINT64, FWP_UINT8,
        },
    },
};

const CONSENT: &str = "HOSTED_WFP_APPWIDE_QA_WITH_INDEPENDENT_SYSTEM_RESCUE";
const FILTER_NOT_FOUND: u32 = 0x8032_0003;
const SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
const SUB: GUID = GUID {
    data1: 0xf6ce4dd2,
    data2: 0xd0ae,
    data3: 0x47f9,
    data4: [0x9c, 0x18, 0x21, 0x4a, 0x81, 0xa9, 0x4c, 0x70],
};
const KEYS: [GUID; 2] = [
    GUID {
        data1: 0xe4186af1,
        data2: 0x949a,
        data3: 0x4d85,
        data4: [0x82, 0x48, 0x73, 0xea, 0xe4, 0xb5, 0x17, 0x39],
    },
    GUID {
        data1: 0x38df6702,
        data2: 0xa741,
        data3: 0x45b7,
        data4: [0xab, 0xc4, 0x05, 0x96, 0x6e, 0xad, 0x67, 0x20],
    },
];
const LAYERS: [GUID; 2] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
];
fn equal_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.0) };
    }
}
struct Filter(*mut FWPM_FILTER0);
impl Drop for Filter {
    fn drop(&mut self) {
        let mut p = self.0.cast::<c_void>();
        unsafe { FwpmFreeMemory0(&mut p) };
    }
}
struct SubLayer(*mut FWPM_SUBLAYER0);
impl Drop for SubLayer {
    fn drop(&mut self) {
        let mut p = self.0.cast::<c_void>();
        unsafe { FwpmFreeMemory0(&mut p) };
    }
}
fn engine() -> Result<Engine, String> {
    let mut h: HANDLE = null_mut();
    let code = unsafe { FwpmEngineOpen0(null(), 10, null(), null(), &mut h) };
    if code != 0 || h.is_null() {
        return Err(format!("BFE engine unavailable: {code}"));
    }
    Ok(Engine(h))
}
fn get_filter(h: HANDLE, key: &GUID) -> Result<Option<Filter>, String> {
    let mut p = null_mut();
    let code = unsafe { FwpmFilterGetByKey0(h, key, &mut p) };
    if code == FILTER_NOT_FOUND {
        return Ok(None);
    }
    if code != 0 || p.is_null() {
        return Err(format!("BFE filter readback failed: {code}"));
    }
    Ok(Some(Filter(p)))
}
fn get_sublayer(h: HANDLE) -> Result<Option<SubLayer>, String> {
    let mut p = null_mut();
    let code = unsafe { FwpmSubLayerGetByKey0(h, &SUB, &mut p) };
    if code == SUBLAYER_NOT_FOUND {
        return Ok(None);
    }
    if code != 0 || p.is_null() {
        return Err(format!("BFE sublayer readback failed: {code}"));
    }
    Ok(Some(SubLayer(p)))
}
// Readback protects cleanup from deleting a foreign or unexpectedly reconfigured filter.
// The raw BFE AppId bytes stay in process memory and never enter JSON/logs.
fn verify(h: HANDLE) -> Result<([bool; 2], bool), String> {
    let sub = get_sublayer(h)?;
    if let Some(ref s) = sub {
        let v = unsafe { &*s.0 };
        if !equal_guid(&v.subLayerKey, &SUB)
            || v.flags & FWPM_SUBLAYER_FLAG_PERSISTENT == 0
            || v.weight != 0xd800
        {
            return Err("Unexpected AppId-wide sublayer: refuse modification".into());
        }
    }
    let mut present = [false; 2];
    let mut first_app: Option<Vec<u8>> = None;
    for index in 0..2 {
        let found = get_filter(h, &KEYS[index])?;
        let Some(f) = found else {
            continue;
        };
        let v = unsafe { &*f.0 };
        if !equal_guid(&v.filterKey, &KEYS[index])
            || !equal_guid(&v.subLayerKey, &SUB)
            || !equal_guid(&v.layerKey, &LAYERS[index])
            || v.flags & FWPM_FILTER_FLAG_PERSISTENT == 0
            || v.action.r#type != FWP_ACTION_BLOCK
            || v.numFilterConditions != 1
            || v.filterCondition.is_null()
        {
            return Err("Unexpected AppId-wide filter: refuse modification".into());
        }
        let c = unsafe { &*v.filterCondition };
        if !equal_guid(&c.fieldKey, &FWPM_CONDITION_ALE_APP_ID)
            || c.matchType != FWP_MATCH_EQUAL
            || c.conditionValue.r#type != FWP_BYTE_BLOB_TYPE
        {
            return Err("Unexpected AppId-wide condition: refuse modification".into());
        }
        let blob = unsafe { c.conditionValue.Anonymous.byteBlob };
        if blob.is_null() || unsafe { (*blob).size } == 0 || unsafe { (*blob).data.is_null() } {
            return Err("Malformed AppId-wide BFE identity".into());
        }
        let app = unsafe { std::slice::from_raw_parts((*blob).data, (*blob).size as usize) };
        if let Some(ref previous) = first_app {
            if previous.as_slice() != app {
                return Err("IPv4 and IPv6 AppIds differ: refuse modification".into());
            }
        } else {
            first_app = Some(app.to_vec());
        }
        present[index] = true;
    }
    Ok((present, sub.is_some()))
}
fn require_consent(token: &str) -> Result<(), String> {
    if token != CONSENT {
        return Err("Explicit AppId-wide hosted QA consent required".into());
    }
    Ok(())
}
fn remove_inner(h: HANDLE) -> Result<(), String> {
    let (filters, sub) = verify(h)?;
    for index in 0..2 {
        if filters[index] {
            let code = unsafe { FwpmFilterDeleteByKey0(h, &KEYS[index]) };
            if code != 0 {
                return Err(format!("AppId-wide cleanup failed: {code}"));
            }
        }
    }
    if sub {
        let code = unsafe { FwpmSubLayerDeleteByKey0(h, &SUB) };
        if code != 0 {
            return Err(format!("AppId-wide sublayer cleanup failed: {code}"));
        }
    }
    if verify(h)? != ([false; 2], false) {
        return Err("AppId-wide cleanup incomplete".into());
    }
    Ok(())
}
pub fn remove(token: &str) -> Result<Value, String> {
    require_consent(token)?;
    remove_inner(engine()?.0)?;
    Ok(json!({"ok":true,"qa_filters_and_sublayer_absent":true,
             "protected_fail_closed":false,"release_accepted":false}))
}
pub fn status(token: &str) -> Result<Value, String> {
    require_consent(token)?;
    let (filters, sub) = verify(engine()?.0)?;
    Ok(
        json!({"ok":true,"qa_ipv4_present":filters[0],"qa_ipv6_present":filters[1],
             "qa_sublayer_present":sub,"redacted":true,"ndisrd_modified":false,
             "protected_fail_closed":false,"dns_leak_free":false,
             "win10_11_accepted":false,"release_accepted":false}),
    )
}
pub fn arm(path: &str, token: &str) -> Result<Value, String> {
    require_consent(token)?;
    if std::env::var("GITHUB_ACTIONS").ok().as_deref() != Some("true")
        || std::env::var("RUNNER_ENVIRONMENT").ok().as_deref() != Some("github-hosted")
        || std::env::var("FLOWBRIDGE_WFP_APPWIDE_SYSTEM_RESCUE_ARMED")
            .ok()
            .as_deref()
            != Some("1")
    {
        return Err("GitHub-hosted Windows and independent SYSTEM rescue required".into());
    }
    let p = Path::new(path);
    let temp = std::env::var("RUNNER_TEMP").map_err(|_| "Hosted temp unavailable")?;
    if p.file_name().and_then(|f| f.to_str()) != Some("FlowBridgeWfpLabClient.exe")
        || !p.is_file()
        || !std::fs::canonicalize(p)
            .map_err(|_| "QA image unavailable")?
            .starts_with(std::fs::canonicalize(temp).map_err(|_| "QA temp unavailable")?)
    {
        return Err("Only a copied temporary QA image is accepted".into());
    }
    let (canonical, _) = canonical_file_handle_paths(p)?;
    let app = lookup_app(&canonical)?;
    let e = engine()?;
    if verify(e.0)? != ([false; 2], false) {
        return Err("Stale AppId-wide QA objects: refuse overwrite".into());
    }
    let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sub.subLayerKey = SUB;
    sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sub.weight = 0xd800;
    let mut name: Vec<u16> = "FlowBridge hosted appwide deny canary\0"
        .encode_utf16()
        .collect();
    sub.displayData.name = name.as_mut_ptr();
    let code = unsafe { FwpmSubLayerAdd0(e.0, &sub, null_mut()) };
    if code != 0 {
        return Err(format!("AppId-wide sublayer add failed: {code}"));
    }
    let inserted = (|| -> Result<(), String> {
        for index in 0..2 {
            let mut condition: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
            condition.conditionValue.Anonymous.byteBlob = app.0;
            let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            f.filterKey = KEYS[index];
            f.flags = FWPM_FILTER_FLAG_PERSISTENT;
            f.layerKey = LAYERS[index];
            f.subLayerKey = SUB;
            f.weight.r#type = FWP_UINT8;
            f.weight.Anonymous.uint8 = 15;
            f.action.r#type = FWP_ACTION_BLOCK;
            f.numFilterConditions = 1;
            f.filterCondition = &mut condition;
            let mut title: Vec<u16> = "FlowBridge hosted appwide test filter\0"
                .encode_utf16()
                .collect();
            f.displayData.name = title.as_mut_ptr();
            let mut id = 0;
            let code = unsafe { FwpmFilterAdd0(e.0, &f, null_mut(), &mut id) };
            if code != 0 || id == 0 {
                return Err(format!("AppId-wide filter add failed: {code}"));
            }
        }
        if verify(e.0)? != ([true; 2], true) {
            return Err("AppId-wide BFE readback incomplete".into());
        }
        Ok(())
    })();
    if let Err(error) = inserted {
        let rollback = remove_inner(e.0);
        return Err(format!(
            "{error}; cleanup {}",
            if rollback.is_ok() {
                "verified"
            } else {
                "failed; independent SYSTEM rescue required"
            }
        ));
    }
    println!(
        "{}",
        json!({"ok":true,"kind":"hosted_appwide_ipv4_ipv6_deny_canary",
        "bfe_readback":true,"persistent":true,"appid_only_no_port_filter":true,
        "ipv4_ipv6":true,"system_rescue_prearmed":true,"ndisrd_modified":false,
        "protected_fail_closed":false,"dns_leak_free":false,"release_accepted":false})
    );
    std::io::stdout()
        .flush()
        .map_err(|_| "QA stdout flush failed")?;
    thread::sleep(Duration::from_secs(90));
    Ok(json!({"ok":true,"cleanup_required":true,"release_accepted":false}))
}


// RELEASE-BLOCKER EXPERIMENT, NOT A PRODUCT EXEMPTION:
// A *dynamic-session* SOFT permit (no CLEAR_ACTION_RIGHT flag) can precede
// the persistent AppId block inside the SAME BFE sublayer. Other sublayers
// must retain their ability to block the packet. Only one disposable hosted
// QA executable and one ephemeral high destination port may be admitted.
// The permit is auto-removed when the owning BFE session/process closes.
// Production would additionally require verified NDISRD diversion BEFORE
// granting a permit, SSH health monitoring, fail-closed rollback and proof
// that existing established flows are revoked on any failure.
const SOFT_LEASE_CONSENT: &str = "HOSTED_WFP_SOFT_LEASE_QA_WITH_INDEPENDENT_SYSTEM_RESCUE";
const SOFT_KEYS: [GUID; 2] = [
    GUID {
        data1: 0xcf3d384e,
        data2: 0x59a7,
        data3: 0x4b09,
        data4: [0xab, 0x13, 0x96, 0x6d, 0xf8, 0xe5, 0xc9, 0x14],
    },
    GUID {
        data1: 0xade55f97,
        data2: 0x6191,
        data3: 0x452f,
        data4: [0xa8, 0x63, 0xb5, 0x11, 0xba, 0xcc, 0x02, 0x79],
    },
];

fn require_soft_lease_consent(token: &str) -> Result<(), String> {
    if token != SOFT_LEASE_CONSENT {
        return Err("Exact experimental soft-lease consent required".into());
    }
    Ok(())
}

fn soft_lease_readback(h: HANDLE) -> Result<[bool; 2], String> {
    let mut present = [false; 2];
    for index in 0..2 {
        let Some(filter) = get_filter(h, &SOFT_KEYS[index])? else {
            continue;
        };
        let value = unsafe { &*filter.0 };
        if !equal_guid(&value.filterKey, &SOFT_KEYS[index])
            || !equal_guid(&value.subLayerKey, &SUB)
            || !equal_guid(&value.layerKey, &LAYERS[index])
            || value.flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) != 0
            || value.action.r#type != FWP_ACTION_PERMIT
            || value.numFilterConditions != 2
            || value.filterCondition.is_null()
            || value.weight.r#type != FWP_UINT64
        {
            return Err("Unexpected BFE lease identity/soft-action: refuse acceptance".into());
        }
        let raw_weight = unsafe { value.weight.Anonymous.uint64 };
        if raw_weight.is_null() || unsafe { *raw_weight } != u64::MAX {
            return Err("BFE lease weight was not pinned above persistent DENY".into());
        }
        let conditions = unsafe { std::slice::from_raw_parts(value.filterCondition, 2) };
        if !equal_guid(&conditions[0].fieldKey, &FWPM_CONDITION_ALE_APP_ID)
            || conditions[0].matchType != FWP_MATCH_EQUAL
            || conditions[0].conditionValue.r#type != FWP_BYTE_BLOB_TYPE
            || !equal_guid(&conditions[1].fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT)
            || conditions[1].matchType != FWP_MATCH_EQUAL
            || conditions[1].conditionValue.r#type != FWP_UINT16
            || !(49152..=65534).contains(&unsafe { conditions[1].conditionValue.Anonymous.uint16 })
        {
            return Err("Unexpected BFE lease conditions".into());
        }
        present[index] = true;
    }
    Ok(present)
}

pub fn soft_lease_status(token: &str) -> Result<Value, String> {
    require_soft_lease_consent(token)?;
    let e = engine()?;
    let present = soft_lease_readback(e.0)?;
    Ok(json!({"ok":true,"soft_lease_ipv4_present":present[0],
        "soft_lease_ipv6_present":present[1],"dynamic_session_only":true,
        "hard_permit":false,"ndisrd_modified":false,"protected_fail_closed":false,
        "dns_leak_free":false,"win10_11_accepted":false,"release_accepted":false}))
}

pub fn soft_lease(path: &str, port: u16, token: &str) -> Result<Value, String> {
    require_soft_lease_consent(token)?;
    if std::env::var("GITHUB_ACTIONS").ok().as_deref() != Some("true")
        || std::env::var("RUNNER_ENVIRONMENT").ok().as_deref() != Some("github-hosted")
        || std::env::var("FLOWBRIDGE_WFP_APPWIDE_SYSTEM_RESCUE_ARMED")
            .ok().as_deref() != Some("1")
    {
        return Err("Hosted Windows and independent SYSTEM persistent-rule rescue required".into());
    }
    if !(49152..=65534).contains(&port) {
        return Err("Experimental permit requires one ephemeral QA destination port".into());
    }
    let p = Path::new(path);
    let temp = std::env::var("RUNNER_TEMP").map_err(|_| "Hosted temp unavailable")?;
    if p.file_name().and_then(|f| f.to_str()) != Some("FlowBridgeWfpLabClient.exe")
        || !p.is_file()
        || !std::fs::canonicalize(p)
            .map_err(|_| "QA image unavailable")?
            .starts_with(std::fs::canonicalize(temp).map_err(|_| "QA temp unavailable")?)
    {
        return Err("One copied temporary QA image is required".into());
    }
    let (canonical, _) = canonical_file_handle_paths(p)?;
    let app = lookup_app(&canonical)?;
    let e = engine()?;
    if verify(e.0)? != ([true; 2], true) {
        return Err("Both persistent AppId deny filters must be installed FIRST".into());
    }
    if soft_lease_readback(e.0)? != [false; 2] {
        return Err("Another soft lease already exists: refuse takeover".into());
    }

    // Compare AppId bytes to the pinned persistent rules: the caller cannot
    // open an exception for some OTHER executable in the QA sublayer.
    let selected_blob = app.0;
    if selected_blob.is_null() || unsafe { (*selected_blob).data.is_null() } {
        return Err("Missing selected AppId".into());
    }
    let selected = unsafe {
        std::slice::from_raw_parts((*selected_blob).data, (*selected_blob).size as usize)
    };
    for key in &KEYS {
        let persistent = get_filter(e.0, key)?
            .ok_or_else(|| "Persistent filter disappeared during lease setup".to_owned())?;
        let condition = unsafe { &*(*persistent.0).filterCondition };
        let blob = unsafe { condition.conditionValue.Anonymous.byteBlob };
        if blob.is_null()
            || unsafe { (*blob).data.is_null() }
            || unsafe { (*blob).size as usize } != selected.len()
            || unsafe {
                std::slice::from_raw_parts((*blob).data, (*blob).size as usize)
            } != selected
        {
            return Err("Soft lease and persistent AppId identities differ".into());
        }
    }

    let mut dynamic: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
    dynamic.flags = FWPM_SESSION_FLAG_DYNAMIC;
    let mut handle: HANDLE = null_mut();
    let opened = unsafe { FwpmEngineOpen0(null(), 10, null(), &dynamic, &mut handle) };
    if opened != 0 || handle.is_null() {
        return Err(format!("Dynamic BFE lease session unavailable: {opened}"));
    }
    let lease = Engine(handle);
    // The explicit UINT64 weight is higher than the persistent block's
    // BFE-generated FWP_UINT8 range (15). Default filter PERMIT is SOFT.
    // This does NOT override other sublayers' Firewall/third-party BLOCK.
    let mut weight = u64::MAX;
    for index in 0..2 {
        let mut conditions: [FWPM_FILTER_CONDITION0; 2] = [unsafe { std::mem::zeroed() }; 2];
        conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        conditions[0].conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        conditions[0].conditionValue.Anonymous.byteBlob = app.0;
        conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[1].matchType = FWP_MATCH_EQUAL;
        conditions[1].conditionValue.r#type = FWP_UINT16;
        conditions[1].conditionValue.Anonymous.uint16 = port;
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.filterKey = SOFT_KEYS[index];
        f.layerKey = LAYERS[index];
        f.subLayerKey = SUB;
        f.flags = 0; // Never set CLEAR_ACTION_RIGHT (hard permit).
        f.weight.r#type = FWP_UINT64;
        f.weight.Anonymous.uint64 = &mut weight;
        f.action.r#type = FWP_ACTION_PERMIT;
        f.numFilterConditions = 2;
        f.filterCondition = conditions.as_mut_ptr();
        let mut title: Vec<u16> = "FlowBridge hosted dynamic SOFT permit QA\0"
            .encode_utf16().collect();
        f.displayData.name = title.as_mut_ptr();
        let mut id = 0;
        let added = unsafe { FwpmFilterAdd0(lease.0, &f, null_mut(), &mut id) };
        if added != 0 || id == 0 {
            return Err(format!("Dynamic soft permit add failed: {added}"));
        }
    }
    if soft_lease_readback(e.0)? != [true; 2] {
        return Err("Dynamic soft permit readback incomplete".into());
    }
    println!("{}", json!({"ok":true,"kind":"hosted_same_sublayer_soft_permit_lease",
        "soft_permit_readback":true,"lease_port_restricted":true,"dynamic_session":true,
        "persistent_deny_still_present":true,"hard_permit":false,
        "ndisrd_modified":false,"protected_fail_closed":false,
        "dns_leak_free":false,"release_accepted":false}));
    std::io::stdout().flush().map_err(|_| "QA stdout flush failed")?;
    thread::sleep(Duration::from_secs(45));
    // Dropping lease ALWAYS closes this dynamic BFE engine, removing its
    // permit even if the process ends normally. A crash closes it in the OS.
    drop(lease);
    Ok(json!({"ok":true,"soft_lease_expired":true,
        "protected_fail_closed":false,"release_accepted":false}))
}
