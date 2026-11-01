//! Real WFP dynamic app-ID/TCP-port enforcement, disposable Windows QA only.
//! Dynamic BFE filters vanish on guard death: NOT protected fail-closed,
//! WFP/NDISRD ordering, an arbitrary application route or release acceptance.
#![cfg(windows)]
use serde_json::{json, Value};
use std::{
    ffi::{c_void, OsStr},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{null, null_mut},
    thread,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0,
        FwpmGetAppIdFromFileName0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_PROTOCOL,
        FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
        FWPM_SUBLAYER_UNIVERSAL, FWP_ACTION_BLOCK, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_EMPTY,
        FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT8,
    },
};

const CONSENT: &str = "DYNAMIC_WFP_QA_LOOPBACK_ONLY";
const CLIENT: &str = "FlowBridgeWfpLabClient.exe";
const RPC_C_AUTHN_WINNT: u32 = 10;

struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: successful FwpmEngineOpen0 handle.
        unsafe { FwpmEngineClose0(self.0) };
    }
}
struct AppBlob(*mut FWP_BYTE_BLOB);
impl Drop for AppBlob {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut ptr = self.0.cast::<c_void>();
            // SAFETY: BFE-owned allocation from FwpmGetAppIdFromFileName0.
            unsafe { FwpmFreeMemory0(&mut ptr) };
        }
    }
}

fn validate(path: &str, port: u16, consent: &str) -> Result<(), String> {
    let bytes = path.as_bytes();
    if consent != CONSENT || !(1025..=65534).contains(&port) {
        return Err("WFP lab requires exact consent and high port".into());
    }
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || path.starts_with(r"\\")
        || path.starts_with("//")
        || !Path::new(path).is_file()
        || Path::new(path).file_name().and_then(|n| n.to_str()) != Some(CLIENT)
        || path
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '%'))
        || path.split(['\\', '/']).any(|c| c == "." || c == "..")
    {
        return Err("WFP lab requires an existing dedicated local-drive QA copy".into());
    }
    Ok(())
}

/// Scope is exactly a disposable QA executable, TCP, one high remote port.
/// An actual process crash removes this dynamic filter (NOT persistent).
pub fn guard(path: &str, port: u16, consent: &str) -> Result<Value, String> {
    validate(path, port, consent)?;
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    let mut raw_app: *mut FWP_BYTE_BLOB = null_mut();
    // SAFETY: NUL-terminated file path and valid returned pointer.
    let status = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut raw_app) };
    if status != 0 || raw_app.is_null() {
        return Err(format!("WFP AppId lookup failed: {status}"));
    }
    let app = AppBlob(raw_app);
    // SAFETY: zero is a valid default for these Win32 C repr structures.
    let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    let mut raw: HANDLE = null_mut();
    // SAFETY: local BFE dynamic session with a bounded lifetime.
    let status = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut raw) };
    if status != 0 || raw.is_null() {
        return Err(format!("WFP engine open failed: {status}"));
    }
    let engine = Engine(raw);
    // SAFETY: zero is the documented default for all condition fields.
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
    conditions[2].conditionValue.Anonymous.uint8 = 6;
    let mut display: Vec<u16> = "FlowBridge disposable dynamic QA guard\0"
        .encode_utf16()
        .collect();
    // SAFETY: zero initialized C repr filter, all required fields populated.
    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.displayData.name = display.as_mut_ptr();
    filter.weight.r#type = FWP_EMPTY;
    filter.action.r#type = FWP_ACTION_BLOCK;
    filter.numFilterConditions = 3;
    filter.filterCondition = conditions.as_mut_ptr();
    let mut id = 0;
    // SAFETY: app blob, all conditions and display string are live during call.
    let status = unsafe { FwpmFilterAdd0(engine.0, &filter, null(), &mut id) };
    if status != 0 {
        return Err(format!("WFP dynamic filter add failed: {status}"));
    }
    println!(
        "{}",
        json!({
            "ok":true, "kind":"original_rust_dynamic_wfp_lab",
            "wfp_ale_block_installed":true, "app_id_scoped":true,
            "tcp_port_scoped":true, "guard_seconds_max":20,
            "filter_persistent":false, "ndisrd_touched":false,
            "wfp_ndisrd_ordering_proved":false, "crash_persistent_fail_closed":false,
            "release_accepted":false
        })
    );
    std::io::stdout()
        .flush()
        .map_err(|_| "WFP guard stdout error")?;
    thread::sleep(Duration::from_secs(20));
    Ok(json!({"ok":true, "dynamic_filter_expired":true,
        "crash_persistent_fail_closed":false, "release_accepted":false}))
}

pub fn client(port: u16, consent: &str) -> Result<Value, String> {
    if consent != CONSENT || !(1025..=65534).contains(&port) {
        return Err("WFP QA client consent or port invalid".into());
    }
    let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut tcp = TcpStream::connect_timeout(&endpoint.into(), Duration::from_secs(2))
        .map_err(|_| "WFP QA TCP connect denied")?;
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "WFP QA read timeout setup failed")?;
    tcp.write_all(b"probe").map_err(|_| "WFP QA write failed")?;
    tcp.shutdown(std::net::Shutdown::Write)
        .map_err(|_| "WFP QA half-close failed")?;
    let mut data = Vec::new();
    tcp.read_to_end(&mut data)
        .map_err(|_| "WFP QA read failed")?;
    if data != b"done" {
        return Err("WFP QA response mismatch".into());
    }
    Ok(json!({"ok":true,"real_tcp_half_close":true,"release_accepted":false}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nonlab_targets_and_missing_consent_before_mutation() {
        assert!(validate(r"C:\tmp\FlowBridgeWfpLabClient.exe", 0, CONSENT).is_err());
        assert!(validate(r"C:\tmp\FlowBridgeWfpLabClient.exe", 50001, "DENY").is_err());
        assert!(validate(r"C:\Windows\System32\powershell.exe", 50001, CONSENT).is_err());
        assert!(validate(r"\\server\share\FlowBridgeWfpLabClient.exe", 50001, CONSENT).is_err());
    }
}
