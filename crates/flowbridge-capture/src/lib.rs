//! Original Rust NDISRD integration candidate. Native lab I/O and offline
//! protected-policy tests are distinct from personal Windows acceptance.
pub mod capture_agent;
pub mod capture_pipeline;
pub mod control_plane;
pub mod ndis_session;
pub mod ndis_wire;
pub mod owned_relay;
#[cfg(any(windows, test))]
mod owner_sampling;
pub mod relay;
pub mod relay_probe;

#[cfg(windows)]
mod windows_control_pipe;
#[cfg(all(windows, target_pointer_width = "64"))]
mod windows_ndis_device;
#[cfg(windows)]
mod windows_ndisrd_service;
#[cfg(windows)]
mod windows_packet_filter;
#[cfg(windows)]
pub mod windows_service;
#[cfg(windows)]
pub mod windows_service_management;
#[cfg(windows)]
pub mod windows_tcp_owner;

pub fn driver_status() -> serde_json::Value {
    #[cfg(windows)]
    {
        windows_packet_filter::report()
    }
    #[cfg(not(windows))]
    {
        serde_json::json!({"backend":"ndisapi","supported":false,"packet_capture_active":false,"native_routing_accepted":false,"signature_status":"not_checked","dns_leak_test_passed":false,"driver_installation_attempted":false,"device_opened":false,"api_compatible":false})
    }
}
