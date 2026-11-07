//! Shared corrected Rust NDISRD status; no second independent ABI definition.
#![cfg(windows)]

use serde_json::Value;

pub(super) fn report() -> Value {
    flowbridge_capture::driver_status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_never_makes_capture_or_signature_claims() {
        let value = report();
        assert_eq!(value["backend"], "ndisapi");
        assert_eq!(value["signature_status"], "not_checked");
        assert_eq!(value["packet_capture_active"], false);
        assert_eq!(value["native_routing_accepted"], false);
        assert_eq!(value["dns_leak_test_passed"], false);
        assert_eq!(value["driver_installation_attempted"], false);
        assert_eq!(value["adapter_wire_bytes"], 8836);
    }
}
