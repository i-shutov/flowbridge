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

#[cfg(windows)]
mod windows_readonly {
    use std::{ffi::c_void, mem, net::TcpStream, os::windows::io::AsRawSocket, ptr};
    const SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE: u32 = super::ALE_ENDPOINT_IOCTL_OPCODE; // _WSAIOR(IOC_VENDOR, 205)
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const MAX_APPID_BYTES: usize = 8192;
    #[repr(C)] union IpAddr { v4: u32, v6: [u8; 16] }
    #[repr(C)] struct FwpByteBlob { size: u32, data: *mut u8 }
    #[repr(C)] struct EndpointProperties {
        endpoint_id: u64,
        ip_version: u32,
        local: IpAddr,
        remote: IpAddr,
        ip_protocol: u8,
        local_port: u16,
        remote_port: u16,
        local_token_modified_id: u64,
        mm_sa_id: u64,
        qm_sa_id: u64,
        ipsec_status: u32,
        flags: u32,
        app_id: FwpByteBlob,
    }
    #[derive(Debug)] pub struct EndpointDiagnostic {
        pub id: u64, pub ip_version: u32, pub protocol: u8,
        pub appid_bytes: usize,
    }
    #[derive(Debug)] pub enum ProbeError { Winsock(i32), WrongOutput(u32), Bfe(u32), Lookup(u32), BadProperties }
    #[link(name="ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(s: usize, code: u32, inbuf:*const c_void, inlen:u32,
                    outbuf:*mut c_void, outlen:u32, returned:*mut u32,
                    overlapped:*mut c_void, completion:*mut c_void) -> i32;
        fn WSAGetLastError() -> i32;
    }
    #[link(name="fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineOpen0(server:*const u16, authn:u32, creds:*const c_void,
                           session:*const c_void, engine:*mut *mut c_void) -> u32;
        fn FwpmEngineClose0(engine:*mut c_void) -> u32;
        fn FwpsAleEndpointGetById0(engine:*mut c_void, endpoint:u64,
                                   props:*mut *mut EndpointProperties) -> u32;
        fn FwpmFreeMemory0(memory:*mut *mut c_void);
    }
    struct Engine(*mut c_void);
    impl Drop for Engine { fn drop(&mut self) { unsafe { FwpmEngineClose0(self.0); } } }
    struct Properties(*mut EndpointProperties);
    impl Drop for Properties {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe {
                let mut raw=self.0.cast::<c_void>(); FwpmFreeMemory0(&mut raw);
            }}
        }
    }
    /// Read-only. Consumes NO socket; requires a borrowed *already accepted* TCP stream.
    /// Deliberately private/not invoked by main. No AUTH_CONNECT proof is returned.
    #[allow(dead_code)]
    pub fn inspect_existing_socket(socket: &TcpStream) -> Result<EndpointDiagnostic, ProbeError> {
        let mut id=0u64;
        let mut got=0u32;
        let ret=unsafe { WSAIoctl(socket.as_raw_socket() as usize,
            SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE, ptr::null(), 0,
            (&mut id as *mut u64).cast(), mem::size_of::<u64>() as u32,
            &mut got, ptr::null_mut(), ptr::null_mut()) };
        if ret != 0 { return Err(ProbeError::Winsock(unsafe {WSAGetLastError()})); }
        if got != 8 || id == 0 { return Err(ProbeError::WrongOutput(got)); }
        let mut h=ptr::null_mut();
        let status=unsafe {FwpmEngineOpen0(ptr::null(), RPC_C_AUTHN_WINNT,
                                          ptr::null(), ptr::null(), &mut h)};
        if status != 0 { return Err(ProbeError::Bfe(status)); }
        if h.is_null() { return Err(ProbeError::BadProperties); }
        let engine=Engine(h);
        let mut prop_ptr=ptr::null_mut();
        let status=unsafe {FwpsAleEndpointGetById0(engine.0, id, &mut prop_ptr)};
        let props=Properties(prop_ptr);
        if status != 0 { return Err(ProbeError::Lookup(status)); }
        if props.0.is_null() { return Err(ProbeError::BadProperties); }
        let p=unsafe {&*props.0};
        if p.endpoint_id != id || p.ip_protocol != 6 || p.ip_version > 1
            || p.app_id.size == 0 || p.app_id.size as usize > MAX_APPID_BYTES
            || p.app_id.data.is_null() { return Err(ProbeError::BadProperties); }
        // No dereference/copy of WFP appId or endpoint pointers beyond this scope.
        Ok(EndpointDiagnostic {id,ip_version:p.ip_version,
                               protocol:p.ip_protocol,appid_bytes:p.app_id.size as usize})
    }
    #[test] fn documented_x64_abi_sizes() {
        assert_eq!(mem::size_of::<IpAddr>(),16);
        assert_eq!(mem::size_of::<FwpByteBlob>(),16);
        assert_eq!(mem::size_of::<EndpointProperties>(),104);
        assert_eq!(mem::offset_of!(EndpointProperties,app_id),88);
    }
}

#[cfg(test)] mod tests {
    use super::*;
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
    println!("R63 offline-only. Winsock/BFE functions are not invoked. No original-owner proof.");
}
