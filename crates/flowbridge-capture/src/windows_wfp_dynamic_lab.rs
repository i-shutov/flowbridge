//! Real WFP dynamic app-ID/TCP-port enforcement, disposable Windows QA only.
//! Dynamic BFE filters vanish on guard death: NOT protected fail-closed,
//! WFP/NDISRD ordering, an arbitrary application route or release acceptance.
#![cfg(windows)]
use serde_json::{json, Value};
use std::{
    ffi::c_void,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{null, null_mut},
    thread,
    time::Duration,
};
use windows_sys::core::GUID;
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0,
        FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FWPM_CONDITION_ALE_APP_ID,
        FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0,
        FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_SESSION0,
        FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_BYTE_BLOB,
        FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT8,
    },
};

const CONSENT: &str = "DYNAMIC_WFP_QA_LOOPBACK_ONLY";
const DIAG: &str = "DYNAMIC_WFP_QA_APP_ONLY_DIAGNOSTIC";
const PORT_DIAG: &str = "DYNAMIC_WFP_QA_PORT_ONLY_DIAGNOSTIC";
const CLIENT: &str = "FlowBridgeWfpLabClient.exe";
const RPC_C_AUTHN_WINNT: u32 = 10;
// Disposable QA-only namespace, never persistent or shipped as protected policy.
const QA_SUBLAYER: GUID = GUID {
    data1: 0xa39c7ed8,
    data2: 0x7301,
    data3: 0x44d1,
    data4: [0xb4, 0x54, 0x9d, 0x0e, 0x80, 0xa9, 0x67, 0x3a],
};

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

// A deliberately read-only identity cross-check. An AppId returned from a
// filename is NOT proof that the kernel attached it to any network packet.
// The two BFE blobs stay private; neither path nor raw AppId is reported.
fn lookup_app(path: &Path) -> Result<AppBlob, String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut raw: *mut FWP_BYTE_BLOB = null_mut();
    // SAFETY: Windows null-terminated path and valid out pointer.
    let status = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut raw) };
    if status != 0 || raw.is_null() {
        return Err(format!("WFP AppId lookup failed: {status}"));
    }
    let app = AppBlob(raw);
    // SAFETY: returned successful BFE-owned FWP_BYTE_BLOB, still owned by app.
    let (size, data) = unsafe { ((*app.0).size as usize, (*app.0).data) };
    if size == 0 || size > 16_384 || data.is_null() {
        return Err("Invalid WFP AppId blob".into());
    }
    Ok(app)
}

fn same_app_id(first: &AppBlob, second: &AppBlob) -> bool {
    // SAFETY: blobs passed validation in lookup_app and remain alive.
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts((*first.0).data, (*first.0).size as usize),
            std::slice::from_raw_parts((*second.0).data, (*second.0).size as usize),
        )
    };
    a == b
}

/// Compare the actual running EXE's BFE AppId with the selected disposable
/// QA target, never exposing filenames, IDs, packet data, or process details.
/// This is read-only and DOES NOT authorize interception or protected mode.
pub fn identity_probe(path: &str, consent: &str) -> Result<Value, String> {
    validate(path, 49_152, consent)?;
    if consent != CONSENT {
        return Err("WFP identity probe requires exact QA consent".into());
    }
    let target = lookup_app(Path::new(path))?;
    let own =
        std::env::current_exe().map_err(|_| "Unable to resolve the QA executable".to_owned())?;
    let self_id = lookup_app(&own)?;
    Ok(json!({
        "ok": true,
        "kind": "wfp_qa_running_executable_appid_comparison",
        "own_app_id_equals_target": same_app_id(&self_id, &target),
        "redacted": true,
        "wfp_filter_created": false,
        "ndisrd_modified": false,
        "packet_pid_bound": false,
        "protected_fail_closed": false,
        "release_accepted": false
    }))
}

fn validate(path: &str, port: u16, consent: &str) -> Result<(), String> {
    let bytes = path.as_bytes();
    if (consent != CONSENT && consent != DIAG && consent != PORT_DIAG)
        || !(1025..=65534).contains(&port)
    {
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
    let app_only_diagnostic = consent == DIAG;
    let port_only_diagnostic = consent == PORT_DIAG;
    let app = lookup_app(Path::new(path))?;
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
    // Separate the QA block from same-sublayer terminating permits. Objects
    // registered in this dynamic BFE session vanish when the guard dies.
    let mut name: Vec<u16> = "FlowBridge temporary QA sublayer\0"
        .encode_utf16()
        .collect();
    // SAFETY: zero is a valid C default; no PERSISTENT flag is set.
    let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sublayer.subLayerKey = QA_SUBLAYER;
    sublayer.displayData.name = name.as_mut_ptr();
    sublayer.weight = 0xe000;
    // SAFETY: live engine and valid sublayer for its dynamic lifetime.
    let status = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, null_mut()) };
    if status != 0 {
        return Err(format!("WFP QA dynamic sublayer add failed: {status}"));
    }
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
    filter.subLayerKey = QA_SUBLAYER;
    filter.displayData.name = display.as_mut_ptr();
    // Highest filter weight range *within the private dynamic sublayer*.
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = 15;
    filter.action.r#type = FWP_ACTION_BLOCK;
    // The QA port-only trial is intentionally limited to a single ephemeral
    // real loopback listener on a disposable hosted Windows CI runner. It
    // differentiates actual BFE classification from AppId path matching.
    // Both trials still expire with the dynamic engine/guard.
    if port_only_diagnostic {
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut conditions[1];
    } else {
        filter.numFilterConditions = if app_only_diagnostic { 1 } else { 3 };
        filter.filterCondition = conditions.as_mut_ptr();
    }
    let mut id = 0;
    // SAFETY: app blob, all conditions and display string are live during call.
    let status = unsafe { FwpmFilterAdd0(engine.0, &filter, null_mut(), &mut id) };
    if status != 0 {
        return Err(format!("WFP dynamic filter add failed: {status}"));
    }
    println!(
        "{}",
        json!({
            "ok":true, "kind":"original_rust_dynamic_wfp_lab",
            "wfp_ale_block_installed":true, "app_id_scoped":!port_only_diagnostic,
            "dynamic_private_sublayer":true,
            "tcp_port_scoped":!app_only_diagnostic,
            "diagnostic_app_id_only":app_only_diagnostic,
            "diagnostic_port_only":port_only_diagnostic,
            "guard_seconds_max":20,
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
