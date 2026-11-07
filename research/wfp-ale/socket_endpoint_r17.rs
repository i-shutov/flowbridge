//! R17: clean-room, user-mode, read-only observation of a borrowed TCP socket.
//! No capture/redirect/filter/driver mutation, process lookup or tuple matching.
//! This library does NOT create a kernel owner witness. Endpoint properties have
//! AppId but no PID/creation epoch; redirect blobs are opaque and unattributed.
//! No public constructor, raw-socket input, Clone, Debug or authority promotion.
//!
//! API references: Microsoft Winsock IOCTLs; FwpsAleEndpointGetById0 (fwpsu.h);
//! FWPS_ALE_ENDPOINT_PROPERTIES0 (fwpstypes.h); QUERY_WFP_* redirect IOCTLs.
use std::net::TcpStream;

#[cfg(all(windows, target_pointer_width = "64"))]
const QUERY_ENDPOINT: u32 = 0x5800_00cd;
#[cfg(all(windows, target_pointer_width = "64"))]
const QUERY_RECORDS: u32 = 0x9800_00dc;
#[cfg(all(windows, target_pointer_width = "64"))]
const QUERY_CONTEXT: u32 = 0x9800_00dd;
#[cfg(all(windows, target_pointer_width = "64"))]
const CAP: usize = 65536;

#[derive(Debug, PartialEq, Eq)]
pub enum ProbeError {
    UnsupportedPlatform,
    NotConnected,
    BfeSession(u32),
    BfeSessionClose(u32),
    EndpointLookup(u32),
    InvalidEndpoint,
    InvalidBlob,
    InvalidIoctlOutput,
    Ioctl(u32),
    EndpointChanged,
    FamilyOrProtocolMismatch,
}

struct Query {
    bytes: Vec<u8>,
    error: Option<u32>,
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
impl Query {
    fn endpoint(&self) -> Result<u64, ProbeError> {
        if let Some(code) = self.error {
            return Err(ProbeError::Ioctl(code));
        }
        let bytes: [u8; 8] = self.bytes.as_slice().try_into()
            .map_err(|_| ProbeError::InvalidEndpoint)?;
        let id = u64::from_le_bytes(bytes);
        if id == 0 { return Err(ProbeError::InvalidEndpoint); }
        Ok(id)
    }
}

/// Byte counts are diagnostic only; not a redirect ticket or owner identity.
pub struct RedactedSummary {
    pub app_id_bytes: usize,
    pub redirect_records_bytes: usize,
    pub redirect_records_error: Option<u32>,
    pub redirect_context_bytes: usize,
    pub redirect_context_error: Option<u32>,
    pub attribution_scope: &'static str,
    pub original_process_identity_proved: bool,
    pub g2_admission_allowed: bool,
}

/// Remains tied to the caller's live local socket borrow. Does not authenticate
/// the remote application that caused a proxy to accept a connection.
pub struct LocalSocketObservation<'a> {
    _socket: &'a TcpStream,
    _endpoint: u64,
    app_id: Vec<u8>,
    records: Query,
    context: Query,
}

impl LocalSocketObservation<'_> {
    pub fn redacted(&self) -> RedactedSummary {
        RedactedSummary {
            app_id_bytes: self.app_id.len(),
            redirect_records_bytes: self.records.bytes.len(),
            redirect_records_error: self.records.error,
            redirect_context_bytes: self.context.bytes.len(),
            redirect_context_error: self.context.error,
            attribution_scope: "queried_local_endpoint_only",
            original_process_identity_proved: false,
            g2_admission_allowed: false,
        }
    }
}

/// Query only an existing, caller-owned connected stream. Socket creation,
/// original-owner authentication and any redirection are outside this API.
pub fn inspect(stream: &TcpStream) -> Result<LocalSocketObservation<'_>, ProbeError> {
    #[cfg(all(windows, target_pointer_width = "64"))]
    { native::inspect(stream) }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    { let _ = stream; Err(ProbeError::UnsupportedPlatform) }
}

#[cfg(all(windows, target_pointer_width = "64"))]
mod native {
    use super::*;
    use std::{ffi::c_void, os::windows::io::AsRawSocket, ptr, slice};

    #[repr(C)]
    union Address { v4: u32, v6: [u8; 16] }
    #[repr(C)]
    struct Blob { size: u32, data: *mut u8 }
    #[repr(C)]
    struct EndpointProperties {
        endpoint_id: u64, ip_version: i32,
        local_address: Address, remote_address: Address,
        ip_protocol: u8, local_port: u16, remote_port: u16,
        local_token_modified_id: u64, mm_sa_id: u64, qm_sa_id: u64,
        ipsec_status: u32, flags: u32, app_id: Blob,
    }
    const _: () = assert!(std::mem::size_of::<EndpointProperties>() == 104);
    const _: () = assert!(std::mem::offset_of!(EndpointProperties, app_id) == 88);

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(s: usize, code: u32, input: *const c_void, input_len: u32,
                    output: *mut c_void, output_len: u32, returned: *mut u32,
                    overlapped: *mut c_void, completion: *mut c_void) -> i32;
        fn WSAGetLastError() -> i32;
    }
    #[link(name = "fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineOpen0(server: *const u16, authentication: u32,
            identity: *const c_void, session: *const c_void, engine: *mut *mut c_void) -> u32;
        fn FwpmEngineClose0(engine: *mut c_void) -> u32;
        fn FwpsAleEndpointGetById0(engine: *mut c_void, endpoint: u64,
            result: *mut *mut EndpointProperties) -> u32;
        fn FwpmFreeMemory0(memory: *mut *mut c_void);
    }

    struct Engine(*mut c_void);
    impl Engine {
        fn open() -> Result<Self, ProbeError> {
            let mut handle = ptr::null_mut();
            // Local authenticated query session; no filter operations.
            let status = unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(),
                                                  ptr::null(), &mut handle) };
            let owned = Self(handle);
            if status != 0 || owned.0.is_null() { return Err(ProbeError::BfeSession(status)); }
            Ok(owned)
        }
        fn finish(mut self) -> Result<(), ProbeError> {
            let handle = std::mem::replace(&mut self.0, ptr::null_mut());
            let status = unsafe { FwpmEngineClose0(handle) };
            if status == 0 { Ok(()) } else { Err(ProbeError::BfeSessionClose(status)) }
        }
    }
    impl Drop for Engine {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { FwpmEngineClose0(self.0) }; }
        }
    }
    struct Properties(*mut EndpointProperties);
    impl Drop for Properties {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let mut memory = self.0.cast::<c_void>();
                unsafe { FwpmFreeMemory0(&mut memory) };
            }
        }
    }

    fn query(stream: &TcpStream, code: u32, capacity: usize) -> Result<Query, ProbeError> {
        if !matches!(code, QUERY_ENDPOINT | QUERY_RECORDS | QUERY_CONTEXT)
            || capacity == 0 || capacity > CAP { return Err(ProbeError::InvalidIoctlOutput); }
        let mut bytes = vec![0u8; capacity];
        let mut returned = 0u32;
        // The borrowed stream outlives this synchronous query; buffers are bounded.
        let status = unsafe { WSAIoctl(stream.as_raw_socket() as usize, code,
            ptr::null(), 0, bytes.as_mut_ptr().cast(), capacity as u32,
            &mut returned, ptr::null_mut(), ptr::null_mut()) };
        if status != 0 {
            let error = unsafe { WSAGetLastError() };
            if error <= 0 { return Err(ProbeError::InvalidIoctlOutput); }
            return Ok(Query { bytes: Vec::new(), error: Some(error as u32) });
        }
        if returned == 0 || returned as usize > capacity { return Err(ProbeError::InvalidIoctlOutput); }
        bytes.truncate(returned as usize);
        Ok(Query { bytes, error: None })
    }

    pub(super) fn inspect(stream: &TcpStream) -> Result<LocalSocketObservation<'_>, ProbeError> {
        let address = stream.local_addr().map_err(|_| ProbeError::NotConnected)?;
        stream.peer_addr().map_err(|_| ProbeError::NotConnected)?;
        let engine = Engine::open()?;
        let endpoint = query(stream, QUERY_ENDPOINT, 8)?.endpoint()?;
        let mut raw = ptr::null_mut();
        let status = unsafe { FwpsAleEndpointGetById0(engine.0, endpoint, &mut raw) };
        let allocated = Properties(raw);
        if status != 0 || allocated.0.is_null() { return Err(ProbeError::EndpointLookup(status)); }
        // BFE allocation remains alive through the bounded private copy.
        let props = unsafe { &*allocated.0 };
        if props.endpoint_id != endpoint { return Err(ProbeError::InvalidEndpoint); }
        let version = if address.is_ipv4() { 0 } else { 1 };
        if props.ip_version != version || props.ip_protocol != 6 {
            return Err(ProbeError::FamilyOrProtocolMismatch);
        }
        if props.app_id.data.is_null() || props.app_id.size == 0 || props.app_id.size as usize > CAP {
            return Err(ProbeError::InvalidBlob);
        }
        let app_id = unsafe { slice::from_raw_parts(props.app_id.data, props.app_id.size as usize) }.to_vec();
        let records = query(stream, QUERY_RECORDS, CAP)?;
        let context = query(stream, QUERY_CONTEXT, CAP)?;
        if query(stream, QUERY_ENDPOINT, 8)?.endpoint()? != endpoint {
            return Err(ProbeError::EndpointChanged);
        }
        drop(allocated);
        engine.finish()?;
        Ok(LocalSocketObservation { _socket: stream, _endpoint: endpoint, app_id, records, context })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_short_zero_and_failed_endpoint_queries() {
        for bytes in [vec![], vec![1; 7], vec![1; 9], vec![0; 8]] {
            assert_eq!(Query { bytes, error: None }.endpoint(), Err(ProbeError::InvalidEndpoint));
        }
        assert_eq!(Query { bytes: vec![1; 8], error: Some(10022) }.endpoint(), Err(ProbeError::Ioctl(10022)));
    }
    #[test]
    fn reads_endpoint_without_a_tuple_or_pid() {
        let q = Query { bytes: 17u64.to_le_bytes().to_vec(), error: None };
        assert_eq!(q.endpoint(), Ok(17));
    }
}
