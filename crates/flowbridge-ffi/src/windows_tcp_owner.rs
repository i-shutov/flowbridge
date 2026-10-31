//! Shared Windows IP Helper TCP owner-candidate interface.
//! The independently implemented lookup and native tests live in
//! flowbridge-capture and are reused by this FFI boundary. Neither caller
//! may promote a racy table snapshot into packet-bound authority.
#![cfg(windows)]

pub(super) use flowbridge_capture::windows_tcp_owner::{lookup, OwnerQuery};
