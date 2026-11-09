//! R66: pure Rust offline guard; no FFI, no OS/network access, never original owner proof.
#![forbid(unsafe_code)]
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Diagnostic { Unobserved, Invalid, EndpointHandleOnly }
#[derive(Debug,Clone,Copy)]
pub struct Visible {
 pub callback_seen:bool, pub socket_owned:bool, pub ioctl_wrote_u64:bool,
 pub numeric_handle_equal:bool, pub ale_query_ok:bool, pub appid_equal:bool,
 pub pid_epoch_equal:bool, pub exe_equal:bool, pub redirect_record_equal:bool,
 pub ssh_ready:bool, pub wfp_ready:bool,
}
pub fn assess(x:Visible)->Diagnostic{
 if !x.callback_seen {return Diagnostic::Unobserved}
 if !(x.socket_owned && x.ioctl_wrote_u64 && x.numeric_handle_equal && x.ale_query_ok
  && x.appid_equal && x.pid_epoch_equal && x.exe_equal && x.redirect_record_equal
  && x.ssh_ready && x.wfp_ready) {return Diagnostic::Invalid}
 Diagnostic::EndpointHandleOnly // Numeric equality is not attestation.
}
#[cfg(test)] mod tests {
 use super::*;
 fn all()->Visible{Visible{callback_seen:true,socket_owned:true,ioctl_wrote_u64:true,
 numeric_handle_equal:true,ale_query_ok:true,appid_equal:true,pid_epoch_equal:true,
 exe_equal:true,redirect_record_equal:true,ssh_ready:true,wfp_ready:true}}
 #[test] fn equality_not_original_owner(){assert_eq!(assess(all()),Diagnostic::EndpointHandleOnly);}
 #[test] fn no_callback_is_not_block(){let mut x=all(); x.callback_seen=false;
  assert_eq!(assess(x),Diagnostic::Unobserved);}
 #[test] fn record_mismatch(){let mut x=all();x.redirect_record_equal=false;
  assert_eq!(assess(x),Diagnostic::Invalid);}
 #[test] fn ssh_loss(){let mut x=all();x.ssh_ready=false;
  assert_eq!(assess(x),Diagnostic::Invalid);}
}
fn main(){println!("R66 diagnostic only: no original owner proof");}
