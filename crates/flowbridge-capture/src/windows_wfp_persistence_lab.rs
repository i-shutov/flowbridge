//! TEST-ONLY persistent WFP AppId high-port guard on GitHub-hosted Windows.
//! A separately scheduled SYSTEM cleanup MUST exist before activation.
//! Never call this protected fail-closed or run it on a paid self-hosted runner.
#![cfg(windows)]
use serde_json::{json, Value};
use std::{ffi::c_void, io::Write, path::Path, ptr::{null, null_mut}, thread, time::Duration};
use windows_sys::{core::GUID, Win32::{Foundation::HANDLE,
    NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineOpen0, FwpmEngineClose0, FwpmFilterAdd0, FwpmFilterGetByKey0,
        FwpmFilterDeleteByKey0, FwpmSubLayerAdd0, FwpmSubLayerGetByKey0,
        FwpmSubLayerDeleteByKey0, FwpmFreeMemory0,
        FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_SUBLAYER0,
        FWPM_FILTER_FLAG_PERSISTENT, FWPM_SUBLAYER_FLAG_PERSISTENT,
        FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_PROTOCOL,
        FWPM_CONDITION_IP_REMOTE_PORT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_BYTE_BLOB_TYPE, FWP_UINT16, FWP_UINT8,
        FWP_MATCH_EQUAL, FWP_ACTION_BLOCK,
    },
}};
use crate::windows_wfp_dynamic_lab::{canonical_file_handle_paths, lookup_app};

const CONSENT: &str = "HOSTED_PERSISTENT_WFP_QA_WITH_INDEPENDENT_SYSTEM_RESCUE";
const FILTER_ABSENT: u32 = 0x8032_0003;
const SUBLAYER_ABSENT: u32 = 0x8032_0007;
const SUB: GUID = GUID {
    data1: 0x3d6ac28f, data2: 0x871b, data3: 0x4250,
    data4: [0x91,0xe8,0x13,0x37,0xcb,0x46,0x96,0x12],
};
const KEY: GUID = GUID {
    data1: 0x674d989f, data2: 0x2c54, data3: 0x4e55,
    data4: [0xb7,0x42,0x92,0x3e,0xb7,0xdd,0xf3,0x1b],
};
fn eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2
        && a.data3 == b.data3 && a.data4 == b.data4
}
struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) { unsafe { FwpmEngineClose0(self.0) }; }
}
struct Filter(*mut FWPM_FILTER0);
impl Drop for Filter {
    fn drop(&mut self) {
        let mut p = self.0.cast::<c_void>();
        unsafe { FwpmFreeMemory0(&mut p) };
    }
}
struct Sublayer(*mut FWPM_SUBLAYER0);
impl Drop for Sublayer {
    fn drop(&mut self) {
        let mut p = self.0.cast::<c_void>();
        unsafe { FwpmFreeMemory0(&mut p) };
    }
}
fn engine() -> Result<Engine, String> {
    let mut h: HANDLE = null_mut();
    let code = unsafe { FwpmEngineOpen0(null(), 10, null(), null(), &mut h) };
    if code != 0 || h.is_null() { return Err(format!("QA BFE engine unavailable: {code}")); }
    Ok(Engine(h))
}
fn filter(h: HANDLE) -> Result<Option<Filter>, String> {
    let mut p = null_mut();
    let code = unsafe { FwpmFilterGetByKey0(h, &KEY, &mut p) };
    if code == FILTER_ABSENT { return Ok(None); }
    if code != 0 || p.is_null() { return Err(format!("QA filter readback failed: {code}")); }
    Ok(Some(Filter(p)))
}
fn sublayer(h: HANDLE) -> Result<Option<Sublayer>, String> {
    let mut p = null_mut();
    let code = unsafe { FwpmSubLayerGetByKey0(h, &SUB, &mut p) };
    if code == SUBLAYER_ABSENT { return Ok(None); }
    if code != 0 || p.is_null() { return Err(format!("QA sublayer readback failed: {code}")); }
    Ok(Some(Sublayer(p)))
}
fn verify(h: HANDLE) -> Result<(bool, bool), String> {
    let f = filter(h)?;
    let s = sublayer(h)?;
    if let Some(ref f) = f {
        let v = unsafe { &*f.0 };
        if !eq(&v.filterKey, &KEY) || !eq(&v.subLayerKey, &SUB)
            || v.flags & FWPM_FILTER_FLAG_PERSISTENT == 0
            || v.action.r#type != FWP_ACTION_BLOCK
            || (!eq(&v.layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4)
                && !eq(&v.layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V6))
            || v.numFilterConditions != 3 || v.filterCondition.is_null()
        { return Err("Unexpected QA filter: refuse to touch".into()); }
        let mut app = false;
        let mut port = false;
        let mut protocol = false;
        for condition in unsafe { std::slice::from_raw_parts(v.filterCondition, 3) } {
            if condition.matchType != FWP_MATCH_EQUAL { return Err("Bad QA match".into()); }
            if eq(&condition.fieldKey, &FWPM_CONDITION_ALE_APP_ID)
                && condition.conditionValue.r#type == FWP_BYTE_BLOB_TYPE {
                let blob = unsafe { condition.conditionValue.Anonymous.byteBlob };
                if blob.is_null() || unsafe { (*blob).size } == 0
                    || unsafe { (*blob).data.is_null() }
                { return Err("Bad QA AppId".into()); }
                app = true;
            } else if eq(&condition.fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT)
                && condition.conditionValue.r#type == FWP_UINT16 {
                port = (49152..=65534).contains(&unsafe { condition.conditionValue.Anonymous.uint16 });
            } else if eq(&condition.fieldKey, &FWPM_CONDITION_IP_PROTOCOL)
                && condition.conditionValue.r#type == FWP_UINT8 {
                protocol = matches!(unsafe { condition.conditionValue.Anonymous.uint8 }, 6 | 17);
            } else { return Err("Unexpected QA condition".into()); }
        }
        if !app || !port || !protocol { return Err("QA conditions invalid".into()); }
    }
    if let Some(ref s) = s {
        let v = unsafe { &*s.0 };
        if !eq(&v.subLayerKey, &SUB)
            || v.flags & FWPM_SUBLAYER_FLAG_PERSISTENT == 0 || v.weight != 0xd800
        { return Err("Unexpected QA sublayer: refuse to touch".into()); }
    }
    Ok((f.is_some(), s.is_some()))
}
fn consent(value: &str) -> Result<(), String> {
    if value != CONSENT { return Err("Explicit hosted persistent QA consent required".into()); }
    Ok(())
}
fn remove_inner(h: HANDLE) -> Result<(), String> {
    let (f, s) = verify(h)?;
    if f {
        let code = unsafe { FwpmFilterDeleteByKey0(h, &KEY) };
        if code != 0 { return Err(format!("QA persistent filter cleanup failed: {code}")); }
    }
    if s {
        let code = unsafe { FwpmSubLayerDeleteByKey0(h, &SUB) };
        if code != 0 { return Err(format!("QA persistent sublayer cleanup failed: {code}")); }
    }
    if verify(h)? != (false, false) { return Err("Persistent QA cleanup incomplete".into()); }
    Ok(())
}
pub fn remove(token: &str) -> Result<Value, String> {
    consent(token)?;
    remove_inner(engine()?.0)?;
    Ok(json!({"ok":true,"qa_filter_and_sublayer_absent":true,"protected_fail_closed":false,"release_accepted":false}))
}
pub fn status(token: &str) -> Result<Value, String> {
    consent(token)?;
    let (f,s) = verify(engine()?.0)?;
    Ok(json!({"ok":true,"qa_filter_present":f,"qa_sublayer_present":s,
        "redacted":true,"ndisrd_modified":false,"protected_fail_closed":false,
        "dns_leak_free":false,"win10_11_accepted":false,"release_accepted":false}))
}
pub fn arm(path: &str, port: u16, family: &str, token: &str) -> Result<Value, String> {
    consent(token)?;
    if std::env::var("GITHUB_ACTIONS").ok().as_deref() != Some("true")
        || std::env::var("RUNNER_ENVIRONMENT").ok().as_deref() != Some("github-hosted")
        || std::env::var("FLOWBRIDGE_WFP_QA_SYSTEM_RESCUE_ARMED").ok().as_deref() != Some("1")
    { return Err("Hosted Windows and independent SYSTEM rescue required".into()); }
    if !(49152..=65534).contains(&port) { return Err("High QA destination port required".into()); }
    let (protocol, ipv6) = match family {
        "tcp4" => (6, false), "udp4" => (17, false),
        "tcp6" => (6, true), "udp6" => (17, true),
        _ => return Err("Unknown QA transport".into()),
    };
    let p = Path::new(path);
    let temp = std::env::var("RUNNER_TEMP").map_err(|_| "Hosted temp missing")?;
    if p.file_name().and_then(|f| f.to_str()) != Some("FlowBridgeWfpLabClient.exe")
        || !p.is_file() || !std::fs::canonicalize(p)
            .map_err(|_| "QA EXE missing")?
            .starts_with(std::fs::canonicalize(temp).map_err(|_| "QA temp missing")?)
    { return Err("One copied temporary QA executable required".into()); }
    let (canonical, _) = canonical_file_handle_paths(p)?;
    let app = lookup_app(&canonical)?;
    let e = engine()?;
    if verify(e.0)? != (false, false) { return Err("Stale QA filter: refuse to overwrite".into()); }
    let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sub.subLayerKey = SUB;
    sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sub.weight = 0xd800;
    let mut sub_name: Vec<u16> = "FlowBridge hosted persistent test sublayer\0".encode_utf16().collect();
    sub.displayData.name = sub_name.as_mut_ptr();
    let code = unsafe { FwpmSubLayerAdd0(e.0, &sub, null_mut()) };
    if code != 0 { return Err(format!("QA sublayer add failed: {code}")); }
    let inserted = (|| -> Result<(), String> {
        let mut conditions: [FWPM_FILTER_CONDITION0; 3] = [unsafe { std::mem::zeroed() }; 3];
        conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        conditions[0].conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        conditions[0].conditionValue.Anonymous.byteBlob = app.0;
        conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[1].matchType = FWP_MATCH_EQUAL;
        conditions[1].conditionValue.r#type = FWP_UINT16;
        conditions[1].conditionValue.Anonymous.uint16 = port;
        conditions[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conditions[2].matchType = FWP_MATCH_EQUAL;
        conditions[2].conditionValue.r#type = FWP_UINT8;
        conditions[2].conditionValue.Anonymous.uint8 = protocol;
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.filterKey = KEY;
        f.flags = FWPM_FILTER_FLAG_PERSISTENT;
        f.layerKey = if ipv6 { FWPM_LAYER_ALE_AUTH_CONNECT_V6 } else { FWPM_LAYER_ALE_AUTH_CONNECT_V4 };
        f.subLayerKey = SUB;
        f.weight.r#type = FWP_UINT8;
        f.weight.Anonymous.uint8 = 15;
        f.action.r#type = FWP_ACTION_BLOCK;
        f.numFilterConditions = 3;
        f.filterCondition = conditions.as_mut_ptr();
        let mut name: Vec<u16> = "FlowBridge dedicated high-port persistence canary\0".encode_utf16().collect();
        f.displayData.name = name.as_mut_ptr();
        let mut id = 0;
        let code = unsafe { FwpmFilterAdd0(e.0, &f, null_mut(), &mut id) };
        if code != 0 || id == 0 { return Err(format!("QA filter add failed: {code}")); }
        if verify(e.0)? != (true, true) { return Err("QA BFE persistent readback missing".into()); }
        Ok(())
    })();
    if let Err(error) = inserted {
        let rollback = remove_inner(e.0);
        return Err(format!("{error}; rollback {}",
            if rollback.is_ok() { "verified" } else { "failed; SYSTEM rescue remains armed" }));
    }
    println!("{}",json!({"ok":true,"kind":"hosted_persistent_wfp_canary",
        "bfe_filter_readback_verified":true,"persistent_filter":true,
        "selected_high_port_only":true,"transport":family,
        "system_rescue_prearmed":true,"ndisrd_modified":false,
        "protected_fail_closed":false,"dns_leak_free":false,"release_accepted":false}));
    std::io::stdout().flush().map_err(|_| "QA stdout flush failed")?;
    thread::sleep(Duration::from_secs(25));
    Ok(json!({"ok":true,"persistent_cleanup_required":true,"release_accepted":false}))
}
