//! Real WFP dynamic app-ID/TCP-port enforcement, disposable Windows QA only.
//! Dynamic BFE filters vanish on guard death: NOT protected fail-closed,
//! WFP/NDISRD ordering, an arbitrary application route or release acceptance.
#![cfg(windows)]
use serde_json::{json, Value};
use std::{
    ffi::c_void,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    thread,
    time::Duration,
};
use windows_sys::core::GUID;
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterGetById0, FwpmFreeMemory0,
        FwpmGetAppIdFromFileName0, FwpmNetEventCreateEnumHandle0, FwpmNetEventDestroyEnumHandle0,
        FwpmNetEventEnum0, FwpmSubLayerAdd0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_PROTOCOL,
        FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT0,
        FWPM_NET_EVENT_FLAG_APP_ID_SET, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_SESSION0,
        FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_BYTE_BLOB,
        FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT8,
    },
    Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_DOS, VOLUME_NAME_NT},
    System::Threading::{GetCurrentProcess, QueryFullProcessImageNameW, PROCESS_NAME_NATIVE},
};

const CONSENT: &str = "DYNAMIC_WFP_QA_LOOPBACK_ONLY";
const UDP4_CONSENT: &str = "DYNAMIC_WFP_QA_UDP4_APP_PORT_ONLY";
const TCP6_CONSENT: &str = "DYNAMIC_WFP_QA_TCP6_APP_PORT_ONLY";
const UDP6_CONSENT: &str = "DYNAMIC_WFP_QA_UDP6_APP_PORT_ONLY";
const DIAG: &str = "DYNAMIC_WFP_QA_APP_ONLY_DIAGNOSTIC";
const PORT_DIAG: &str = "DYNAMIC_WFP_QA_PORT_ONLY_DIAGNOSTIC";
const CLIENT: &str = "FlowBridgeWfpLabClient.exe";
const OTHER_CLIENT: &str = "FlowBridgeWfpOtherClient.exe";
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

// Resolve the disposable executable through a real file handle, not merely
// the caller's DOS spelling. The Win32 canonical path is for the documented
// FwpmGetAppIdFromFileName0 API; NT volume paths are read-only comparators.
// Neither path, stable fingerprint, nor process identity enters QA reports.
fn canonical_file_handle_paths(path: &Path) -> Result<(PathBuf, Vec<u16>), String> {
    let file = std::fs::File::open(path)
        .map_err(|_| "WFP QA cannot open executable for canonical path".to_owned())?;
    let final_path = |flags: u32| -> Result<String, String> {
        let mut path_buf = vec![0u16; 16_384];
        // SAFETY: open file handle, allocated UTF-16 buffer and bounded size.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path_buf.as_mut_ptr(),
                path_buf.len() as u32,
                flags,
            )
        };
        if written == 0 || written as usize >= path_buf.len() {
            return Err("WFP QA canonical handle path unavailable".into());
        }
        String::from_utf16(&path_buf[..written as usize])
            .map_err(|_| "WFP QA canonical handle path encoding invalid".to_owned())
    };
    let dos = final_path(VOLUME_NAME_DOS)?;
    let native = final_path(VOLUME_NAME_NT)?;
    let local = dos
        .strip_prefix(r"\\?\")
        .ok_or("WFP QA canonical DOS path lacks a local drive prefix")?;
    if !Path::new(local).is_absolute() || !native.starts_with(r"\Device\") {
        return Err("WFP QA canonical file handle is not a local NT volume".into());
    }
    Ok((PathBuf::from(local), native.encode_utf16().collect()))
}

// Independent read-only native image path from the ACTUALLY RUNNING process.
// Comparing it to the file-handle path is diagnostic, not a network authority.
fn running_process_native_path() -> Result<Vec<u16>, String> {
    let mut path = vec![0u16; 16_384];
    let mut length = path.len() as u32;
    // SAFETY: current-process pseudo handle and valid bounded UTF-16 buffer.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            GetCurrentProcess(),
            PROCESS_NAME_NATIVE,
            path.as_mut_ptr(),
            &mut length,
        )
    };
    if ok == 0 || length == 0 || length as usize >= path.len() {
        return Err("WFP QA running process native image path unavailable".into());
    }
    path.truncate(length as usize);
    Ok(path)
}

fn normalized_native_units(path: &[u16]) -> Vec<u16> {
    let mut units = path.to_vec();
    for unit in &mut units {
        if (b'A' as u16..=b'Z' as u16).contains(unit) {
            *unit += 32;
        } else if *unit == b'/' as u16 {
            *unit = b'\\' as u16;
        }
    }
    units
}

fn native_path_matches_event(path: &[u16], observed: &FWP_BYTE_BLOB) -> bool {
    normalized_utf16_app_id(observed).is_some_and(|units| units == normalized_native_units(path))
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
    let (target_handle_path, _) = canonical_file_handle_paths(Path::new(path))?;
    let target_handle_id = lookup_app(&target_handle_path)?;
    let own =
        std::env::current_exe().map_err(|_| "Unable to resolve the QA executable".to_owned())?;
    let self_id = lookup_app(&own)?;
    let (own_handle_path, own_native) = canonical_file_handle_paths(&own)?;
    let own_handle_id = lookup_app(&own_handle_path)?;
    let process_native = running_process_native_path()?;
    Ok(json!({
        "ok": true,
        "kind": "wfp_qa_running_executable_appid_comparison",
        "own_app_id_equals_target": same_app_id(&self_id, &target),
        "file_handle_native_path_checked":true,
        "own_native_image_equals_handle":
            normalized_native_units(&own_native) == normalized_native_units(&process_native),
        "own_input_appid_equals_handle_canonical":same_app_id(&self_id, &own_handle_id),
        "target_input_appid_equals_handle_canonical":same_app_id(&target, &target_handle_id),
        "redacted": true,
        "wfp_filter_created": false,
        "ndisrd_modified": false,
        "packet_pid_bound": false,
        "protected_fail_closed": false,
        "release_accepted": false
    }))
}

struct FilterReadback(*mut FWPM_FILTER0);
impl Drop for FilterReadback {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut ptr = self.0.cast::<c_void>();
            // SAFETY: the filter was allocated by FwpmFilterGetById0.
            unsafe { FwpmFreeMemory0(&mut ptr) };
        }
    }
}

fn blob_matches(expected: &AppBlob, actual: &FWP_BYTE_BLOB) -> bool {
    let size = actual.size as usize;
    if size == 0 || size > 16_384 || actual.data.is_null() {
        return false;
    }
    // SAFETY: the BFE returned a bounded, non-null blob and the AppBlob is live.
    let actual_bytes = unsafe { std::slice::from_raw_parts(actual.data, size) };
    let expected_bytes =
        unsafe { std::slice::from_raw_parts((*expected.0).data, (*expected.0).size as usize) };
    actual_bytes == expected_bytes
}

fn normalized_utf16_app_id(blob: &FWP_BYTE_BLOB) -> Option<Vec<u16>> {
    // CLASSIFY_DROP header AppId is a UTF-16LE path byte blob. Decode only
    // privately, never serialize the path, bytes, or a stable fingerprint.
    let size = blob.size as usize;
    if !(2..=16_384).contains(&size) || size % 2 != 0 || blob.data.is_null() {
        return None;
    }
    // SAFETY: bounded, non-null BFE-owned event blob during enumeration.
    let bytes = unsafe { std::slice::from_raw_parts(blob.data, size) };
    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    if units.last() == Some(&0) {
        units.pop();
    }
    if units.is_empty() || units.contains(&0) {
        return None;
    }
    for unit in &mut units {
        if (b'A' as u16..=b'Z' as u16).contains(unit) {
            *unit += 32;
        } else if *unit == b'/' as u16 {
            *unit = b'\\' as u16;
        }
    }
    Some(units)
}

fn app_id_unicode_comparison(expected: &AppBlob, observed: &FWP_BYTE_BLOB) -> (bool, bool) {
    // Strict bytes are checked separately; these supplementary counters can
    // diagnose ASCII casing and executable-basename mismatches but must NEVER
    // authorize a user-selected flow or a WFP security rule.
    let expected_blob = unsafe { &*expected.0 };
    let (Some(left), Some(right)) = (
        normalized_utf16_app_id(expected_blob),
        normalized_utf16_app_id(observed),
    ) else {
        return (false, false);
    };
    let left_name = left.rsplit(|&unit| unit == b'\\' as u16).next();
    let right_name = right.rsplit(|&unit| unit == b'\\' as u16).next();
    (
        left == right,
        left_name.is_some() && left_name == right_name,
    )
}

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

/// Read back the actual BFE-serialized filter. Success from FwpmFilterAdd0
/// alone is not evidence that AppId or its type survived registration.
fn verify_bfe_filter(
    engine: HANDLE,
    filter_id: u64,
    app: &AppBlob,
    port: u16,
    app_only: bool,
    port_only: bool,
    ip_protocol: u8,
    ipv6: bool,
) -> Result<(), String> {
    let mut raw: *mut FWPM_FILTER0 = null_mut();
    // SAFETY: live BFE engine, valid output pointer, observed filter ID.
    let status = unsafe { FwpmFilterGetById0(engine, filter_id, &mut raw) };
    if status != 0 || raw.is_null() {
        return Err(format!("WFP QA BFE filter read-back failed: {status}"));
    }
    let stored = FilterReadback(raw);
    // SAFETY: successfully retrieved live BFE filter.
    let filter = unsafe { &*stored.0 };
    let count = if port_only || app_only { 1 } else { 3 };
    let layer = if ipv6 {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6
    } else {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4
    };
    if !same_guid(&filter.layerKey, layer)
        || !same_guid(&filter.subLayerKey, &QA_SUBLAYER)
        || filter.action.r#type != FWP_ACTION_BLOCK
        || filter.numFilterConditions != count
        || filter.filterCondition.is_null()
    {
        return Err("WFP QA BFE stored filter metadata mismatch".into());
    }
    // SAFETY: count is 1 or 3 and BFE returned a non-null condition array.
    let conditions = unsafe { std::slice::from_raw_parts(filter.filterCondition, count as usize) };
    let mut app_seen = false;
    let mut port_seen = false;
    let mut protocol_seen = false;
    for condition in conditions {
        if condition.matchType != FWP_MATCH_EQUAL {
            return Err("WFP QA BFE stored match operator mismatch".into());
        }
        if same_guid(&condition.fieldKey, &FWPM_CONDITION_ALE_APP_ID)
            && condition.conditionValue.r#type == FWP_BYTE_BLOB_TYPE
        {
            let blob = unsafe { condition.conditionValue.Anonymous.byteBlob };
            if blob.is_null() || !blob_matches(app, unsafe { &*blob }) {
                return Err("WFP QA BFE stored AppId bytes mismatch".into());
            }
            app_seen = true;
        } else if same_guid(&condition.fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT)
            && condition.conditionValue.r#type == FWP_UINT16
        {
            if unsafe { condition.conditionValue.Anonymous.uint16 } != port {
                return Err("WFP QA BFE stored remote port mismatch".into());
            }
            port_seen = true;
        } else if same_guid(&condition.fieldKey, &FWPM_CONDITION_IP_PROTOCOL)
            && condition.conditionValue.r#type == FWP_UINT8
        {
            if unsafe { condition.conditionValue.Anonymous.uint8 } != ip_protocol {
                return Err("WFP QA BFE stored IP protocol mismatch".into());
            }
            protocol_seen = true;
        } else {
            return Err("WFP QA BFE returned an unexpected condition or data type".into());
        }
    }
    if app_seen == port_only || port_seen == app_only || protocol_seen != (!app_only && !port_only)
    {
        return Err("WFP QA BFE stored condition set mismatch".into());
    }
    Ok(())
}

struct EventEnumerator {
    engine: HANDLE,
    handle: HANDLE,
}
impl Drop for EventEnumerator {
    fn drop(&mut self) {
        // SAFETY: enumeration handle was allocated for this live BFE engine.
        unsafe { FwpmNetEventDestroyEnumHandle0(self.engine, self.handle) };
    }
}

/// READ-ONLY attestation that the filter-ID received from the disposable QA
/// guard belongs to the expected live dynamic sublayer, layer and TCP port.
/// Never trust an arbitrary user-supplied filter ID or accept it as a PID token.
fn verify_active_qa_filter(engine: HANDLE, filter_id: u64, port: u16) -> Result<bool, String> {
    let mut raw: *mut FWPM_FILTER0 = null_mut();
    // SAFETY: live engine and a bounded integer identifier; no BFE mutation.
    let status = unsafe { FwpmFilterGetById0(engine, filter_id, &mut raw) };
    if status != 0 || raw.is_null() {
        return Ok(false);
    }
    let stored = FilterReadback(raw);
    // SAFETY: a non-null BFE-owned filter pointer is held by stored.
    let filter = unsafe { &*stored.0 };
    if !same_guid(&filter.layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4)
        || !same_guid(&filter.subLayerKey, &QA_SUBLAYER)
        || filter.action.r#type != FWP_ACTION_BLOCK
        || filter.numFilterConditions == 0
        || filter.numFilterConditions > 3
        || filter.filterCondition.is_null()
    {
        return Err("WFP QA event filter is not the expected ephemeral guard".into());
    }
    // SAFETY: the BFE count has been checked within the exact three-condition bound.
    let conditions = unsafe {
        std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize)
    };
    for condition in conditions {
        if same_guid(&condition.fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT)
            && (condition.matchType != FWP_MATCH_EQUAL
                || condition.conditionValue.r#type != FWP_UINT16
                || unsafe { condition.conditionValue.Anonymous.uint16 } != port)
        {
            return Err("WFP QA event filter port mismatch".into());
        }
    }
    Ok(true)
}

/// Bounded, READ-ONLY WFP net-event correlation against one precise live QA
/// filter ID, not just a coincidentally reused localhost TCP port. No event
/// collection/auditing is enabled, and absent events remain INCONCLUSIVE.
/// The filter ID is used in-process only, never persisted to the report.
pub fn event_identity_probe(
    selected_path: &str,
    other_path: &str,
    python_path: &str,
    agent_path: &str,
    port: u16,
    filter_id: u64,
    consent: &str,
) -> Result<Value, String> {
    validate(selected_path, port, consent)?;
    if consent != CONSENT
        || filter_id == 0
        || Path::new(other_path).file_name().and_then(|n| n.to_str()) != Some(OTHER_CLIENT)
        || Path::new(other_path).parent() != Path::new(selected_path).parent()
        || !Path::new(other_path).is_file()
    {
        return Err("WFP QA events require one live filter and two sibling lab EXEs".into());
    }
    let selected = lookup_app(Path::new(selected_path))?;
    let other = lookup_app(Path::new(other_path))?;
    let (selected_handle_path, selected_handle_native) =
        canonical_file_handle_paths(Path::new(selected_path))?;
    let (other_handle_path, other_handle_native) =
        canonical_file_handle_paths(Path::new(other_path))?;
    let selected_handle_app = lookup_app(&selected_handle_path)?;
    let other_handle_app = lookup_app(&other_handle_path)?;
    // These two independent executable paths are read-only comparators.
    // They do not enter the transient WFP filter or a protected policy.
    if !Path::new(python_path).is_file() || !Path::new(agent_path).is_file() {
        return Err("WFP QA source comparator binary missing".into());
    }
    let python = lookup_app(Path::new(python_path))?;
    let agent = lookup_app(Path::new(agent_path))?;
    let mut raw: HANDLE = null_mut();
    // SAFETY: read-only local BFE connection; no dynamic/persistent rule created.
    let status = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), null(), &mut raw) };
    if status != 0 || raw.is_null() {
        return Err(format!(
            "WFP QA event read-only engine open failed: {status}"
        ));
    }
    let engine = Engine(raw);
    let filter_present = verify_active_qa_filter(engine.0, filter_id, port)?;
    if !filter_present {
        return Ok(json!({
            "ok":true,"kind":"read_only_wfp_exact_filter_drop_correlation",
            "query_succeeded":false,"active_qa_filter_verified":false,
            "event_collection_proven":false,"filter_id_redacted":true,
            "read_only":true,"kernel_packet_owner_bound":false,
            "protected_fail_closed":false,"release_accepted":false
        }));
    }
    let mut enum_handle: HANDLE = null_mut();
    // SAFETY: read-only enumeration of the current engine's existing events.
    let status = unsafe { FwpmNetEventCreateEnumHandle0(engine.0, null(), &mut enum_handle) };
    if status != 0 || enum_handle.is_null() {
        return Ok(json!({
            "ok":true,"kind":"read_only_wfp_exact_filter_drop_correlation",
            "query_succeeded":false,"active_qa_filter_verified":true,
            "event_collection_proven":false,"filter_id_redacted":true,
            "read_only":true,"kernel_packet_owner_bound":false,
            "protected_fail_closed":false,"release_accepted":false
        }));
    }
    let enumerator = EventEnumerator {
        engine: engine.0,
        handle: enum_handle,
    };
    let mut events: *mut *mut FWPM_NET_EVENT0 = null_mut();
    let mut returned = 0u32;
    // SAFETY: BFE-allocated bounded array; every element is checked for null.
    let status =
        unsafe { FwpmNetEventEnum0(engine.0, enumerator.handle, 256, &mut events, &mut returned) };
    let mut selected_matches = 0usize;
    let mut selected_handle_native_matches = 0usize;
    let mut other_handle_native_matches = 0usize;
    let mut selected_handle_app_matches = 0usize;
    let mut other_handle_app_matches = 0usize;
    let mut other_matches = 0usize;
    let mut python_matches = 0usize;
    let mut agent_matches = 0usize;
    let mut selected_ascii_normalized = 0usize;
    let mut selected_basename_only = 0usize;
    let mut other_basename_only = 0usize;
    let mut python_basename_only = 0usize;
    let mut agent_basename_only = 0usize;
    let mut valid_unicode_appids = 0usize;
    let mut unmatched = 0usize;
    let mut no_app_id = 0usize;
    let mut unrelated_drop_events = 0usize;
    let mut exact_filter_drops = 0usize;
    if status == 0 && returned <= 256 && !events.is_null() {
        // SAFETY: successful bounded enumeration of BFE-owned event pointers.
        let entries = unsafe { std::slice::from_raw_parts(events, returned as usize) };
        for entry in entries {
            if entry.is_null() {
                continue;
            }
            // SAFETY: the entry is valid until FwpmFreeMemory0 below.
            let event = unsafe { &**entry };
            if event.header.remotePort != port || event.header.ipProtocol != 6 {
                continue;
            }
            if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                continue;
            }
            // SAFETY: the tagged union contains classifyDrop for this event type.
            let drop = unsafe { event.Anonymous.classifyDrop };
            if drop.is_null() {
                continue;
            }
            // SAFETY: BFE owns the classify-drop object until events is freed.
            if unsafe { (*drop).filterId } != filter_id {
                unrelated_drop_events += 1;
                continue;
            }
            exact_filter_drops += 1;
            if event.header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET == 0 {
                no_app_id += 1;
                continue;
            }
            let observed = &event.header.appId;
            if normalized_utf16_app_id(observed).is_some() {
                valid_unicode_appids += 1;
            }
            let (selected_normalized, selected_basename) =
                app_id_unicode_comparison(&selected, observed);
            let (_, other_basename) = app_id_unicode_comparison(&other, observed);
            let (_, python_basename) = app_id_unicode_comparison(&python, observed);
            let (_, agent_basename) = app_id_unicode_comparison(&agent, observed);
            if selected_normalized && !blob_matches(&selected, observed) {
                selected_ascii_normalized += 1;
            }
            if selected_basename && !selected_normalized {
                selected_basename_only += 1;
            }
            if other_basename && !blob_matches(&other, observed) {
                other_basename_only += 1;
            }
            if python_basename && !blob_matches(&python, observed) {
                python_basename_only += 1;
            }
            if agent_basename && !blob_matches(&agent, observed) {
                agent_basename_only += 1;
            }
            if native_path_matches_event(&selected_handle_native, observed) {
                selected_handle_native_matches += 1;
            }
            if native_path_matches_event(&other_handle_native, observed) {
                other_handle_native_matches += 1;
            }
            if blob_matches(&selected_handle_app, observed) {
                selected_handle_app_matches += 1;
            }
            if blob_matches(&other_handle_app, observed) {
                other_handle_app_matches += 1;
            }
            if blob_matches(&selected, observed) {
                selected_matches += 1;
            } else if blob_matches(&other, observed) {
                other_matches += 1;
            } else if blob_matches(&python, observed) {
                python_matches += 1;
            } else if blob_matches(&agent, observed) {
                agent_matches += 1;
            } else {
                unmatched += 1;
            }
        }
    }
    if !events.is_null() {
        let mut ptr = events.cast::<c_void>();
        // SAFETY: allocation owned by BFE; frees all nested net events.
        unsafe { FwpmFreeMemory0(&mut ptr) };
    }
    Ok(json!({
        "ok":true,"kind":"read_only_wfp_exact_filter_drop_correlation",
        "query_succeeded":status == 0 && returned <= 256,
        "active_qa_filter_verified":true,"filter_id_redacted":true,
        "event_collection_proven":exact_filter_drops > 0,
        "exact_qa_filter_classify_drops":exact_filter_drops,
        "unrelated_filter_classify_drops_same_port":unrelated_drop_events,
        "selected_event_appid_matches":selected_matches,
        "other_event_appid_matches":other_matches,
        "python_event_appid_matches":python_matches,
        "agent_event_appid_matches":agent_matches,
        "event_appid_utf16_path_shape_valid":valid_unicode_appids,
        "selected_appid_ascii_case_only_matches":selected_ascii_normalized,
        "selected_basename_only_matches":selected_basename_only,
        "other_basename_only_matches":other_basename_only,
        "python_basename_only_matches":python_basename_only,
        "agent_basename_only_matches":agent_basename_only,
        "file_handle_native_identity_compared":true,
        "selected_input_appid_equals_handle_canonical":
            same_app_id(&selected, &selected_handle_app),
        "other_input_appid_equals_handle_canonical":
            same_app_id(&other, &other_handle_app),
        "selected_native_handle_path_event_matches":selected_handle_native_matches,
        "other_native_handle_path_event_matches":other_handle_native_matches,
        "selected_canonical_handle_appid_event_matches":selected_handle_app_matches,
        "other_canonical_handle_appid_event_matches":other_handle_app_matches,
        "event_appid_expected_source_identity_complete":
            selected_matches == 1 && other_matches == 1 && python_matches == 1,
        "other_or_unresolved_event_appid":unmatched,
        "exact_filter_events_without_appid":no_app_id,
        "bounded_scan_max":256,"redacted":true,"read_only":true,
        "filter_or_auditing_changed":false,"kernel_packet_owner_bound":false,
        "protected_fail_closed":false,"release_accepted":false
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
    guard_protocol(path, port, consent, 6, false)
}

/// Actual IPv4 UDP AppId+destination-port denial, strictly a disposable
/// high-port localhost QA fixture. Never intended for DNS/53, NDISRD
/// interception or crash-persistent policy. The selected EXE is the only
/// one affected; independent sibling and Python UDP must remain healthy.
pub fn guard_udp4(path: &str, port: u16, consent: &str) -> Result<Value, String> {
    if consent != UDP4_CONSENT {
        return Err("WFP UDP QA requires separate exact consent".into());
    }
    validate(path, port, CONSENT)?;
    guard_protocol(path, port, consent, 17, false)
}

/// Native Windows IPv6, disposable app-specific high-port TCP guard only.
pub fn guard_tcp6(path: &str, port: u16, consent: &str) -> Result<Value, String> {
    if consent != TCP6_CONSENT {
        return Err("WFP IPv6 TCP QA requires separate exact consent".into());
    }
    validate(path, port, CONSENT)?;
    guard_protocol(path, port, consent, 6, true)
}

/// Native Windows IPv6, disposable app-specific high-port UDP guard only.
pub fn guard_udp6(path: &str, port: u16, consent: &str) -> Result<Value, String> {
    if consent != UDP6_CONSENT {
        return Err("WFP IPv6 UDP QA requires separate exact consent".into());
    }
    validate(path, port, CONSENT)?;
    guard_protocol(path, port, consent, 17, true)
}

fn guard_protocol(
    path: &str,
    port: u16,
    consent: &str,
    ip_protocol: u8,
    ipv6: bool,
) -> Result<Value, String> {
    if ip_protocol != 6 && ip_protocol != 17 {
        return Err("WFP QA transport protocol unsupported".into());
    }
    let app_only_diagnostic = consent == DIAG;
    let port_only_diagnostic = consent == PORT_DIAG;
    let (canonical_path, _native_path) = canonical_file_handle_paths(Path::new(path))?;
    let app = lookup_app(&canonical_path)?;
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
    conditions[2].conditionValue.Anonymous.uint8 = ip_protocol;
    let mut display: Vec<u16> = "FlowBridge disposable dynamic QA guard\0"
        .encode_utf16()
        .collect();
    // SAFETY: zero initialized C repr filter, all required fields populated.
    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.layerKey = if ipv6 {
        FWPM_LAYER_ALE_AUTH_CONNECT_V6
    } else {
        FWPM_LAYER_ALE_AUTH_CONNECT_V4
    };
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
    verify_bfe_filter(
        engine.0,
        id,
        &app,
        port,
        app_only_diagnostic,
        port_only_diagnostic,
        ip_protocol,
        ipv6,
    )?;
    println!(
        "{}",
        json!({
            "ok":true, "kind":"original_rust_dynamic_wfp_lab",
            "wfp_ale_block_installed":true, "bfe_filter_readback_verified":true,
            // BFE-generated ephemeral filter identifier only. QA parent
            // consumes it synchronously, never writes it to artifacts/logs.
            "ephemeral_filter_id":id,
            "app_id_scoped":!port_only_diagnostic,
            "app_id_from_canonical_file_handle":true,
            "dynamic_private_sublayer":true,
            "tcp_port_scoped":ip_protocol == 6 && !app_only_diagnostic,
            "udp_ipv4_port_scoped":ip_protocol == 17 && !ipv6,
            "udp_ipv6_port_scoped":ip_protocol == 17 && ipv6,
            "ipv6_ale_layer":ipv6,
            "ip_protocol":ip_protocol,
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

fn probe_tcp_half_close(endpoint: SocketAddr) -> Result<Value, String> {
    let mut tcp = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))
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

pub fn client(port: u16, consent: &str) -> Result<Value, String> {
    if consent != CONSENT || !(1025..=65534).contains(&port) {
        return Err("WFP QA client consent or port invalid".into());
    }
    probe_tcp_half_close(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into())
}

/// Second, independent hosted-Windows QA diagnostic: the destination IPv4
/// must be currently assigned to this same host. The UDP bind is strictly a
/// local-address ownership check; it sends no packets or changes networking.
/// This is NOT evidence that the test traversed an external physical NIC.
pub fn client_local_interface_ipv4(
    address: &str,
    port: u16,
    consent: &str,
) -> Result<Value, String> {
    if consent != CONSENT || !(1025..=65534).contains(&port) {
        return Err("WFP QA local-interface consent or port invalid".into());
    }
    let ip: Ipv4Addr = address
        .parse()
        .map_err(|_| "WFP QA local-interface IPv4 invalid")?;
    let octets = ip.octets();
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || octets[0] == 0
        || octets[0] == 255
        || (octets[0] == 169 && octets[1] == 254)
    {
        return Err("WFP QA requires a non-loopback assigned IPv4".into());
    }
    let binding = UdpSocket::bind(SocketAddrV4::new(ip, 0))
        .map_err(|_| "WFP QA IPv4 is not bound to a local interface")?;
    drop(binding);
    probe_tcp_half_close(SocketAddrV4::new(ip, port).into())
}

/// Real UDP/IPv4 localhost canary with explicit bounded receive timeout.
/// A selected-app BFE DENY may fail send_to or suppress the echo; both
/// outcomes must also be cross-checked against independent allowed clients.
pub fn client_udp4(port: u16, consent: &str) -> Result<Value, String> {
    if consent != UDP4_CONSENT || !(1025..=65534).contains(&port) {
        return Err("WFP UDP QA client consent or port invalid".into());
    }
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| "WFP UDP QA bind failed")?;
    socket
        .set_read_timeout(Some(Duration::from_millis(900)))
        .map_err(|_| "WFP UDP QA receive timeout setup failed")?;
    let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let sent = socket
        .send_to(b"probe", endpoint)
        .map_err(|_| "WFP UDP QA datagram denied")?;
    if sent != 5 {
        return Err("WFP UDP QA datagram send incomplete".into());
    }
    let mut received = [0u8; 8];
    let (n, peer) = socket
        .recv_from(&mut received)
        .map_err(|_| "WFP UDP QA echo not received")?;
    if peer != endpoint.into() || received[..n] != *b"done" {
        return Err("WFP UDP QA echo mismatch".into());
    }
    Ok(json!({
        "ok":true, "real_udp_ipv4":true, "loopback_only":true,
        "ndisrd_touched":false, "dns_leak_free":false,
        "protected_fail_closed":false, "release_accepted":false
    }))
}

/// Actual IPv6 TCP/half-close loopback probe, not DNS or packet-ownership evidence.
pub fn client_tcp6(port: u16, consent: &str) -> Result<Value, String> {
    if consent != TCP6_CONSENT || !(1025..=65534).contains(&port) {
        return Err("WFP IPv6 TCP QA consent or port invalid".into());
    }
    probe_tcp_half_close(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0).into())?;
    Ok(json!({
        "ok":true, "real_tcp_ipv6":true, "loopback_only":true,
        "ndisrd_touched":false, "dns_leak_free":false,
        "protected_fail_closed":false, "release_accepted":false
    }))
}

/// Actual IPv6 UDP echo with explicit deadline and independent server oracle.
pub fn client_udp6(port: u16, consent: &str) -> Result<Value, String> {
    if consent != UDP6_CONSENT || !(1025..=65534).contains(&port) {
        return Err("WFP IPv6 UDP QA consent or port invalid".into());
    }
    let socket = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        .map_err(|_| "WFP IPv6 UDP bind failed")?;
    socket
        .set_read_timeout(Some(Duration::from_millis(900)))
        .map_err(|_| "WFP IPv6 UDP timeout failed")?;
    let endpoint = SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0);
    if socket
        .send_to(b"probe", endpoint)
        .map_err(|_| "WFP IPv6 UDP denied")?
        != 5
    {
        return Err("WFP IPv6 UDP partial send".into());
    }
    let mut received = [0u8; 8];
    let (n, peer) = socket
        .recv_from(&mut received)
        .map_err(|_| "WFP IPv6 UDP echo not received")?;
    if peer != endpoint.into() || received[..n] != *b"done" {
        return Err("WFP IPv6 UDP echo mismatch".into());
    }
    Ok(json!({
        "ok":true, "real_udp_ipv6":true, "loopback_only":true,
        "ndisrd_touched":false, "dns_leak_free":false,
        "protected_fail_closed":false, "release_accepted":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nonlab_targets_and_missing_consent_before_mutation() {
        assert!(validate(r"C:\tmp\FlowBridgeWfpLabClient.exe", 0, CONSENT).is_err());
        assert!(validate(r"C:\tmp\FlowBridgeWfpLabClient.exe", 50001, "DENY").is_err());
        assert!(guard_udp4(r"C:\tmp\FlowBridgeWfpLabClient.exe", 50001, "DENY").is_err());
        assert!(client_udp4(53, UDP4_CONSENT).is_err());
        assert!(client_udp4(50001, "NO_CONSENT").is_err());
        assert!(guard_tcp6(r"C:\tmp\FlowBridgeWfpLabClient.exe", 50001, "DENY").is_err());
        assert!(guard_udp6(r"C:\tmp\FlowBridgeWfpLabClient.exe", 50001, "DENY").is_err());
        assert!(client_tcp6(53, TCP6_CONSENT).is_err());
        assert!(client_udp6(53, UDP6_CONSENT).is_err());
        assert!(client_tcp6(50001, "DENY").is_err());
        assert!(client_udp6(50001, "DENY").is_err());
        assert!(validate(r"C:\Windows\System32\powershell.exe", 50001, CONSENT).is_err());
        assert!(validate(r"\\server\share\FlowBridgeWfpLabClient.exe", 50001, CONSENT).is_err());
        assert!(event_identity_probe(
            r"C:\Windows\System32\powershell.exe",
            r"C:\Windows\System32\not-a-lab.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\powershell.exe",
            50001,
            0,
            CONSENT
        )
        .is_err());
    }
}
