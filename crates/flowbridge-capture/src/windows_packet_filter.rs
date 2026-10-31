//! Read-only status; sharing the SAME packed wire implementation as the agent.
#![cfg(windows)]
use serde_json::{json, Value};

pub(super) fn report() -> Value {
    let mut value = json!({
        "backend":"ndisapi","supported":cfg!(target_pointer_width="64"),
        "device_opened":false,"api_compatible":false,"driver_api_version":null,
        "error":null,"win32_error":null,"signature_status":"not_checked",
        "driver_installation_attempted":false,"packet_capture_active":false,
        "native_routing_accepted":false,"dns_leak_test_passed":false,
        "adapter_inventory_status":"not_checked","adapter_inventory":null,
        "adapter_count":null,"adapter_error":null,"adapter_wire_bytes":8836,
        "service":crate::windows_ndisrd_service::report()
    });
    #[cfg(target_pointer_width = "64")]
    {
        match crate::windows_ndis_device::Driver::open(false) {
            Err(error) => { value["error"] = json!(error.operation); value["win32_error"] = json!(error.code); }
            Ok(mut driver) => {
                value["device_opened"] = json!(true);
                match driver.version() {
                    Err(error) => { value["error"] = json!(error.operation); value["win32_error"] = json!(error.code); }
                    Ok(version) => {
                        value["api_compatible"] = json!(true);
                        value["driver_api_version"] = json!(format!("0x{version:08x}"));
                        match driver.adapters() {
                            Ok(adapters) => {
                                value["adapter_count"] = json!(adapters.len());
                                value["adapter_inventory_status"] = json!("read_only_ok");
                                value["adapter_inventory"] = json!(adapters.iter().map(|a| json!({
                                    "name":a.name,"medium":a.medium,"mtu":a.mtu,"mac":a.mac,"handle_present":true
                                })).collect::<Vec<_>>());
                            }
                            Err(error) => { value["adapter_inventory_status"] = json!("failed"); value["adapter_error"] = json!(error.to_string()); }
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(target_pointer_width = "64"))]
    { value["error"] = json!("unsupported_architecture"); }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_status_does_not_make_capture_signature_or_install_claims() {
        let v = report();
        assert_eq!(v["backend"], "ndisapi"); assert_eq!(v["signature_status"], "not_checked");
        assert_eq!(v["packet_capture_active"], false); assert_eq!(v["native_routing_accepted"], false);
        assert_eq!(v["dns_leak_test_passed"], false); assert_eq!(v["driver_installation_attempted"], false);
        assert_eq!(v["adapter_wire_bytes"], 8836);
    }
}
