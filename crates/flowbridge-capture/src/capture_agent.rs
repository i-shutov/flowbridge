//! Safe Rust diagnostic/lab surface. No arbitrary service launch or privileged
//! SSH execution. Protected application redirect is intentionally unavailable.
use crate::ndis_wire;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn capabilities() -> Value {
    json!({
        "product":"FlowBridgeAgent", "implementation":"independent_rust",
        "platform_supported":cfg!(all(windows, target_pointer_width="64")),
        "ndisrd_separately_installed":true, "proxifyre_required":false,
        "vendor_driver_bundled":false, "custom_wfp_required":false,
        "native_owner_binding_accepted":false, "protected_redirect_available":false,
        "foreground_control_ipc_available":cfg!(windows), "scm_service_available":cfg!(windows),
        "scm_protected_native_mode_available":false,
        "native_tcp_owner_candidate_selftest":cfg!(windows),
        "dns_leak_free":false, "release_accepted":false,
        "modes":["status","observe_lab","observe_owner_candidates_lab","passthrough_lab","relay_loopback_probe","foreground_explicit_socks_control","scm_explicit_socks_candidate","owner_selftest_read_only"],
        "abi":{"adapters":ndis_wire::ADAPTER_LIST_BYTES,"mode":ndis_wire::MODE_BYTES,
            "request":ndis_wire::REQUEST_BYTES,"packet_header":ndis_wire::PACKET_HEADER_BYTES,
            "packet_capacity":ndis_wire::PACKET_BUFFER_BYTES}
    })
}

pub fn status() -> Value {
    let mut value = capabilities();
    #[cfg(windows)]
    {
        value["driver"] = crate::windows_packet_filter::report();
        value["scm"] = crate::windows_ndisrd_service::report();
    }
    #[cfg(not(windows))]
    {
        value["driver"] = json!({"supported":false});
    }
    value
}

/// Actual native Windows IP Helper two-snapshot process-epoch selftest using
/// only a disposable, self-owned loopback TCP socket. This never authenticates
/// any NDISRD packet, enables any divert mode or logs executable paths.
pub fn owner_self_test() -> Result<Value, String> {
    #[cfg(windows)]
    {
        crate::windows_tcp_owner::self_test()
    }
    #[cfg(not(windows))]
    {
        Err("read-only owner selftest requires native Windows IP Helper".into())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabRequest {
    pub adapter_name: String,
    pub duration_ms: u64,
    pub consent: String,
    #[serde(default)]
    pub passthrough: bool,
    #[serde(default)]
    pub owner_candidates: bool,
}

fn validate(request: &LabRequest) -> Result<(), String> {
    if !(1..=60_000).contains(&request.duration_ms)
        || request.adapter_name.is_empty()
        || request.adapter_name.len() > 255
        || !request.adapter_name.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err("Invalid bounded duration or adapter name".into());
    }
    if request.owner_candidates && request.passthrough {
        return Err("IP Helper candidate sampling is read-only and cannot divert".into());
    }
    if request.owner_candidates && request.duration_ms > 15_000 {
        return Err("Owner snapshot observation is limited to 15 seconds".into());
    }
    let required = if request.owner_candidates {
        "LISTEN_ONLY_OWNER_CANDIDATES"
    } else if request.passthrough {
        "EXPERIMENTAL_DIVERT_AND_REINJECT"
    } else {
        "LISTEN_ONLY"
    };
    if request.consent != required {
        return Err(format!(
            "Explicit consent must be {required}; this is not protected mode"
        ));
    }
    Ok(())
}

pub fn run_lab(request: LabRequest) -> Result<Value, String> {
    validate(&request)?;
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        run_native(request)
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    {
        Err("NDISRD laboratory mode requires Windows x64".into())
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn run_native(request: LabRequest) -> Result<Value, String> {
    use crate::ndis_session::{LabMode, PacketSession};
    use crate::windows_ndis_device::Driver;
    use std::time::{Duration, Instant};
    let scm = crate::windows_ndisrd_service::report();
    if scm["service_registered"] != true
        || scm["kernel_driver_type"] != true
        || scm["service_state"] != "running"
    {
        return Err(
            "NDISRD kernel-driver service is not confirmed running; no activation attempted".into(),
        );
    }
    let mut device = Driver::open(true).map_err(|e| e.to_string())?;
    let version = device.version().map_err(|e| e.to_string())?;
    let adapters = device.adapters().map_err(|e| e.to_string())?;
    let adapter = adapters
        .iter()
        .find(|a| a.name == request.adapter_name)
        .ok_or("Exact adapter name not found; no mode change attempted")?;
    if adapter.medium != 0
        || adapter.mtu == 0
        || usize::from(adapter.mtu) + 14 > ndis_wire::MAX_FRAME_BYTES
    {
        return Err("Unsupported media or MTU; no mode change attempted".into());
    }
    let mode = if request.passthrough {
        LabMode::Passthrough
    } else {
        LabMode::Observe
    };
    let start = Instant::now();
    let mut session =
        PacketSession::start(&mut device, adapter.handle, mode).map_err(|e| e.to_string())?;
    let mut failure = None;
    let mut owner_sample = crate::owner_sampling::Sampler::default();
    while start.elapsed() < Duration::from_millis(request.duration_ms) {
        let result = if request.owner_candidates {
            session.poll_observe(128, &mut |direction, frame| {
                owner_sample.observe(direction, frame, |local, remote| {
                    let query = crate::windows_tcp_owner::OwnerQuery { local, remote };
                    match crate::windows_tcp_owner::lookup(query) {
                        Ok(result)
                            if result["found"] == true
                                && result["two_snapshots_consistent"] == true
                                && result["authorizes_capture"] == false
                                && result["native_packet_attribution_proved"] == false =>
                        {
                            crate::owner_sampling::Candidate::ConsistentSnapshot
                        }
                        Ok(result) if result["found"] == false => {
                            crate::owner_sampling::Candidate::Missing
                        }
                        _ => crate::owner_sampling::Candidate::Uncertain,
                    }
                });
            })
        } else {
            session.poll(128)
        };
        if let Err(error) = result {
            failure = Some(error.to_string());
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let stats = session.stats();
    let cleanup = session.close();
    let report = json!({
        "product":"FlowBridgeAgent", "mode":if request.owner_candidates {"observe_owner_candidates_lab"} else if request.passthrough {"passthrough_lab"} else {"observe_lab"},
        "driver_version":format!("0x{version:08x}"), "elapsed_ms":start.elapsed().as_millis(),
        "observed_packets":stats.observed,"outgoing_packets":stats.outgoing,"incoming_packets":stats.incoming,
        "injected_original_packets":stats.injected,"bytes":stats.bytes,"out_of_band_vlan_packets":stats.metadata_vlan,
        "packet_activity_observed":stats.observed > 0,
        "loop_completed":failure.is_none(),"error":failure,
        "rollback_confirmed":cleanup.is_ok(),"rollback_error":cleanup.err().map(|e| e.to_string()),
        "signature_status":"not_checked", "protected_redirect_available":false,"dns_leak_free":false,
        "win10_11_acceptance":false,"release_accepted":false,
        "packet_payload_saved":false,"adapter_name_saved":false,
        "owner_candidate_sampling":if request.owner_candidates {owner_sample.report()} else {json!({"requested":false})},
        "native_packet_attribution_proved":false,"authorizes_capture":false,
        "note":"Lab operation only. Passthrough sends originals; observe never reinjects. Mode 0 is normal networking, not a kill switch."
    });
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lab_input_cannot_enable_protected_mode_or_hide_consent() {
        let good = LabRequest {
            adapter_name: "adapter".into(),
            duration_ms: 20,
            consent: "LISTEN_ONLY".into(),
            passthrough: false,
            owner_candidates: false,
        };
        assert!(validate(&good).is_ok());
        let mut bad = good;
        bad.passthrough = true;
        assert!(validate(&bad).is_err());
        bad.consent = "EXPERIMENTAL_DIVERT_AND_REINJECT".into();
        assert!(validate(&bad).is_ok());
        bad.duration_ms = 60_001;
        assert!(validate(&bad).is_err());
        bad.duration_ms = 20;
        bad.owner_candidates = true;
        assert!(validate(&bad).is_err());
        bad.passthrough = false;
        assert!(validate(&bad).is_err());
        bad.consent = "LISTEN_ONLY_OWNER_CANDIDATES".into();
        assert!(validate(&bad).is_ok());
        bad.duration_ms = 15_001;
        assert!(validate(&bad).is_err());
        assert!(serde_json::from_str::<LabRequest>(
            r#"{"adapter_name":"a","duration_ms":1,"consent":"LISTEN_ONLY","protected":true}"#
        )
        .is_err());
        let cap = capabilities();
        assert_eq!(cap["protected_redirect_available"], false);
        assert_eq!(cap["vendor_driver_bundled"], false);
        assert_eq!(cap["release_accepted"], false);
        assert_eq!(cap["native_owner_binding_accepted"], false);
    }
}
