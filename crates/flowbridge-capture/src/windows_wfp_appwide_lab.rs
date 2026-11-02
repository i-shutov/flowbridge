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
            FwpmSubLayerGetByKey0, FWPM_CONDITION_ALE_APP_ID, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
            FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
            FWP_ACTION_BLOCK, FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT8,
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
