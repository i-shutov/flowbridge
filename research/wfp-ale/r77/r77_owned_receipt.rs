//! R77: no-I/O, no-driver typestate model. This is not WFP authentication.
#![forbid(unsafe_code)]

pub const FIRST_CAP: usize = 65_536;
pub const MAX_CAP: usize = 1_048_576;
pub const CONTEXT_LEN: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum Error { NoReceipt, InvalidLength, InsufficientUnbounded, RetryFailed, ContextInvalid, ClaimFailed }
#[derive(Debug, Clone, Copy)]
pub enum ResultCode {
    Ok(usize), Insufficient { required: usize },
    WsaInvalid, Pending, Unsupported, NetDown,
}

/// Unique owned acceptance capability. The socket is never exposed by a raw ID.
pub struct Accepted<S> { socket: S }
pub struct WithRecords<S> { socket: S, pub bytes: usize }
pub struct WithContext<S> { socket: S }
pub struct ClaimAttempted<S> { socket: S, pub succeeded: bool }

impl<S> Accepted<S> {
    pub fn new(socket: S) -> Self { Self { socket } }

    /// Models synchronous WSAIoctl responses on ONE accepted socket.
    /// No automatic retry on WSAEINVAL; only ERROR_INSUFFICIENT_BUFFER with
    /// greater bounded required length permits one same-socket re-query.
    pub fn records(self, first: ResultCode, retry: Option<ResultCode>)
        -> Result<WithRecords<S>, Error>
    {
        let n = match first {
            ResultCode::Ok(n) if n > 0 && n <= FIRST_CAP => n,
            ResultCode::Ok(_) => return Err(Error::InvalidLength),
            ResultCode::Insufficient { required }
                if required > FIRST_CAP && required <= MAX_CAP => {
                    match retry {
                        Some(ResultCode::Ok(n)) if n > 0 && n <= required => n,
                        _ => return Err(Error::RetryFailed),
                    }
                }
            ResultCode::Insufficient { .. } => return Err(Error::InsufficientUnbounded),
            _ => return Err(Error::NoReceipt),
        };
        Ok(WithRecords { socket: self.socket, bytes: n })
    }
}
impl<S> WithRecords<S> {
    /// Context must be read from the same owned accepted socket and checked.
    /// A 128-byte buffer is NOT itself proof of a valid kernel context.
    pub fn context(self, byte_len: usize, independently_validated: bool)
        -> Result<WithContext<S>, Error>
    {
        if byte_len != CONTEXT_LEN || !independently_validated {
            return Err(Error::ContextInvalid);
        }
        Ok(WithContext { socket: self.socket })
    }
}
impl<S> WithContext<S> {
    /// A terminal mock CLAIM. Kernel provenance is out of scope.
    /// Consumption prevents replay of this capability in safe Rust.
    pub fn claim_once(self, success: bool) -> ClaimAttempted<S> {
        ClaimAttempted { socket: self.socket, succeeded: success }
    }
}
impl<S> ClaimAttempted<S> {
    pub fn into_socket_if_claimed(self) -> Result<S, Error> {
        if self.succeeded { Ok(self.socket) } else { Err(Error::ClaimFailed) }
    }
}

#[cfg(test)] mod tests {
    use super::*;
    fn start() -> Accepted<u64> { Accepted::new(314159) }
    #[test] fn ordinary_candidate_is_not_automatic_admission() {
        let receipt = start().records(ResultCode::Ok(64), None).unwrap();
        let checked = receipt.context(CONTEXT_LEN, true).unwrap();
        assert_eq!(checked.claim_once(true).into_socket_if_claimed().unwrap(), 314159);
    }
    #[test] fn reject_zero() { assert!(matches!(start().records(ResultCode::Ok(0), None), Err(Error::InvalidLength))); }
    #[test] fn reject_oversize() { assert!(matches!(start().records(ResultCode::Ok(FIRST_CAP+1), None), Err(Error::InvalidLength))); }
    #[test] fn reject_ambiguous_einval() { assert!(matches!(start().records(ResultCode::WsaInvalid, Some(ResultCode::Ok(42))), Err(Error::NoReceipt))); }
    #[test] fn no_size_zero_probe() { assert!(matches!(start().records(ResultCode::WsaInvalid, None), Err(Error::NoReceipt))); }
    #[test] fn bounded_retry() { assert_eq!(start().records(ResultCode::Insufficient{required:FIRST_CAP+1}, Some(ResultCode::Ok(FIRST_CAP+1))).unwrap().bytes,FIRST_CAP+1); }
    #[test] fn too_large_required() { assert!(matches!(start().records(ResultCode::Insufficient{required:MAX_CAP+1}, Some(ResultCode::Ok(1))), Err(Error::InsufficientUnbounded))); }
    #[test] fn non_growing_required() { assert!(matches!(start().records(ResultCode::Insufficient{required:FIRST_CAP}, Some(ResultCode::Ok(4))), Err(Error::InsufficientUnbounded))); }
    #[test] fn second_failure_is_terminal() { assert!(matches!(start().records(ResultCode::Insufficient{required:MAX_CAP}, Some(ResultCode::Pending)), Err(Error::RetryFailed))); }
    #[test] fn missing_second_is_terminal() { assert!(matches!(start().records(ResultCode::Insufficient{required:MAX_CAP}, None), Err(Error::RetryFailed))); }
    #[test] fn pending_not_accepted() { assert!(matches!(start().records(ResultCode::Pending, None), Err(Error::NoReceipt))); }
    #[test] fn unsupported_not_accepted() { assert!(matches!(start().records(ResultCode::Unsupported, None), Err(Error::NoReceipt))); }
    #[test] fn network_down_not_accepted() { assert!(matches!(start().records(ResultCode::NetDown, None), Err(Error::NoReceipt))); }
    #[test] fn context_len_must_match() { assert!(matches!(start().records(ResultCode::Ok(42),None).unwrap().context(127,true),Err(Error::ContextInvalid))); }
    #[test] fn context_must_be_validated() { assert!(matches!(start().records(ResultCode::Ok(42),None).unwrap().context(128,false),Err(Error::ContextInvalid))); }
    #[test] fn claim_failure_is_terminal() { assert!(matches!(start().records(ResultCode::Ok(42),None).unwrap().context(128,true).unwrap().claim_once(false).into_socket_if_claimed(),Err(Error::ClaimFailed))); }
}
