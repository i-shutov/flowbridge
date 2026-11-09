//! R63 / clean-room Rust user-mode read-only diagnostic experiment.
//! Default binary and tests perform ZERO Windows, Winsock, network or BFE calls.
//! The Windows module declares an opt-in function for an ALREADY OWNED accepted TCP socket;
//! it creates NO sockets, drivers, filters, services, or policies. NEVER an owner proof.
#![forbid(unsafe_op_in_unsafe_fn)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assessment { Unobserved, InvalidDiagnostic, EndpointOnlyNotOrigin }

#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub dispatched: bool,
    pub socket_query_ok: bool,
    pub returned_bytes: u32,
    pub engine_open_ok: bool,
    pub endpoint_get_ok: bool,
    pub endpoint_equal: bool,
    pub family_supported: bool,
    pub appid_present: bool,
    pub protocol_tcp: bool,
    pub owner_notification_live: bool,
    pub ssh_ready: bool,
    pub wfp_ready: bool,
}

pub fn assess(o: Observation) -> Assessment {
    if !o.dispatched { return Assessment::Unobserved; }
    if !o.socket_query_ok || o.returned_bytes != 8 || !o.engine_open_ok
        || !o.endpoint_get_ok || !o.endpoint_equal || !o.family_supported
        || !o.appid_present || !o.protocol_tcp || !o.owner_notification_live
        || !o.ssh_ready || !o.wfp_ready
    { return Assessment::InvalidDiagnostic; }
    // A valid socket-endpoint diagnostic has NO ORIGINAL_CLASSIFY_OWNER witness.
    Assessment::EndpointOnlyNotOrigin
}

/// From the Windows SDK: mstcpip.h `_WSAIOR(IOC_VENDOR, 205)`.
/// Microsoft-generated windows-rs metadata: 1476395213u32 (0x580000CD).
/// Do not confuse with `_WSAIOR(IOC_WS2, 3)` (= 0x48000003).
pub const ALE_ENDPOINT_IOCTL_OPCODE: u32 = 0x4000_0000 | 0x1800_0000 | 205;

#[cfg(all(windows, not(target_pointer_width = "64")))]
compile_error!("R63 FFI layout audit is restricted to Windows x64; x86 layout not validated");

// R65 safety quarantine: the public allocation/free ownership contract for
// FwpsAleEndpointGetById0's returned FWPS_ALE_ENDPOINT_PROPERTIES0** is NOT proven.
// Do not ship a live FFI implementation and do not guess an allocator.
// This module deliberately has no WSAIoctl, BFE, or memory-free imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeReadiness { DisabledAllocatorOwnershipUnverified }

pub const fn probe_readiness() -> ProbeReadiness {
    ProbeReadiness::DisabledAllocatorOwnershipUnverified
}

#[cfg(windows)]
mod windows_readonly {
    use std::net::TcpStream;
    #[derive(Debug)] pub struct EndpointDiagnostic {
        pub id: u64, pub ip_version: u32, pub protocol: u8, pub appid_bytes: usize,
    }
    #[derive(Debug, PartialEq, Eq)]
    pub enum ProbeError { AllocatorOwnershipUnverified }
    /// No syscalls, no FFI, no socket modifications, even when called on Windows.
    /// Original unsafe prototype is preserved in git history (R63/R64), not in live code.
    #[allow(dead_code)]
    pub fn inspect_existing_socket(_socket: &TcpStream) -> Result<EndpointDiagnostic, ProbeError> {
        Err(ProbeError::AllocatorOwnershipUnverified)
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn r65_quarantine_is_unconditional() {
        assert_eq!(probe_readiness(), ProbeReadiness::DisabledAllocatorOwnershipUnverified);
    }

    fn base()->Observation { Observation {dispatched:true,socket_query_ok:true,
        returned_bytes:8,engine_open_ok:true,endpoint_get_ok:true,endpoint_equal:true,
        family_supported:true,appid_present:true,protocol_tcp:true,
        owner_notification_live:true,ssh_ready:true,wfp_ready:true} }
    #[test] fn endpoint_ioctl_matches_windows_sdk() {
        assert_eq!(ALE_ENDPOINT_IOCTL_OPCODE, 1476395213u32);
        assert_eq!(ALE_ENDPOINT_IOCTL_OPCODE, 0x5800_00CD);
        assert_ne!(ALE_ENDPOINT_IOCTL_OPCODE, 0x4800_0003);
    }
    #[test] fn diagnostic_is_not_orig_owner_proof() {
        assert_eq!(assess(base()), Assessment::EndpointOnlyNotOrigin);
    }
    #[test] fn no_callback_is_not_os_block() {
        let mut x=base();x.dispatched=false;assert_eq!(assess(x),Assessment::Unobserved);
    }
    #[test] fn short_output_rejected() {
        for n in [0,1,4,7,9,16] {let mut x=base();x.returned_bytes=n;
            assert_eq!(assess(x),Assessment::InvalidDiagnostic);}
    }
    #[test] fn wrong_ipv6_or_ipv4_rejected() {
        let mut x=base();x.family_supported=false;assert_eq!(assess(x),Assessment::InvalidDiagnostic);
    }
    #[test] fn udp_rejected() {
        let mut x=base();x.protocol_tcp=false;assert_eq!(assess(x),Assessment::InvalidDiagnostic);
    }
    #[test] fn bfe_permissions_and_endpoint_recycling_rejected() {
        let mut x=base();x.engine_open_ok=false;assert_eq!(assess(x),Assessment::InvalidDiagnostic);
        x=base();x.endpoint_equal=false;assert_eq!(assess(x),Assessment::InvalidDiagnostic);
    }
    #[test] fn ssh_wfp_loss_rejected() {
        let mut x=base();x.ssh_ready=false;assert_eq!(assess(x),Assessment::InvalidDiagnostic);
        x=base();x.wfp_ready=false;assert_eq!(assess(x),Assessment::InvalidDiagnostic);
    }
    #[test] fn delayed_death_observation_is_not_owner_attestation() {
        let mut x=base();x.owner_notification_live=false;assert_eq!(assess(x),Assessment::InvalidDiagnostic);
        assert_eq!(assess(base()),Assessment::EndpointOnlyNotOrigin);
    }
}

fn main() {
    println!("R65 quarantined: allocator ownership unverified; NO Winsock/BFE calls or original-owner proof.");
}
