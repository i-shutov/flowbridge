//! R67 pure Rust source-only negative model: no FFI/OS/network/driver.
#![forbid(unsafe_code)]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Decision { OutsideTcp, OutsideAuth, Unobserved, BlockRequested, ModelPermitOnly }
#[derive(Clone,Copy)]
pub struct Input {
 pub tcp:bool, pub current_selected:bool, pub original_selected:bool,
 pub redirect_seen:bool, pub auth_seen:bool, pub ticket:bool,
 pub epoch:bool, pub endpoint:bool, pub records:bool,
 pub healthy:bool, pub loss:bool,
}
#[derive(Clone,Copy,Debug)]
pub struct Assessment {
 pub redirect_filter_matches:bool, pub auth_filter_matches:bool,
 pub decision:Decision, pub original_owner_proven:bool, pub no_direct_proven:bool,
}
pub fn assess(x:Input)->Assessment{
 let r=x.tcp&&x.current_selected;
 let a=x.tcp&&x.original_selected;
 let d=if !x.tcp{Decision::OutsideTcp}
 else if !a{Decision::OutsideAuth}
 else if !x.auth_seen{Decision::Unobserved}
 else if !(r&&x.redirect_seen&&x.ticket&&x.epoch&&x.endpoint&&x.records&&x.healthy&&!x.loss) {Decision::BlockRequested}
 else {Decision::ModelPermitOnly};
 Assessment{redirect_filter_matches:r,auth_filter_matches:a,decision:d,
 original_owner_proven:false,no_direct_proven:false}
}
#[cfg(test)]mod tests{
 use super::*;
 fn x()->Input{Input{tcp:true,current_selected:true,original_selected:true,redirect_seen:true,auth_seen:true,ticket:true,epoch:true,endpoint:true,records:true,healthy:true,loss:false}}
 #[test]fn selected_original_foreign_current_has_no_redirect_receipt(){
  let mut v=x();v.current_selected=false;let o=assess(v);
  assert!(!o.redirect_filter_matches&&o.auth_filter_matches);
  assert_eq!(o.decision,Decision::BlockRequested);}
 #[test]fn missing_dispatch_unobserved(){let mut v=x();v.auth_seen=false;
  assert_eq!(assess(v).decision,Decision::Unobserved);}
 #[test]fn current_only_outside_auth(){let mut v=x();v.original_selected=false;
  assert!(assess(v).redirect_filter_matches);
  assert_eq!(assess(v).decision,Decision::OutsideAuth);}
 #[test]fn udp_outside(){let mut v=x();v.tcp=false;
  assert_eq!(assess(v).decision,Decision::OutsideTcp);}
 #[test]fn no_permit_is_proof(){let o=assess(x());
  assert_eq!(o.decision,Decision::ModelPermitOnly);
  assert!(!o.original_owner_proven&&!o.no_direct_proven);}
 #[test]fn loss_requests_block(){let mut v=x();v.loss=true;
  assert_eq!(assess(v).decision,Decision::BlockRequested);}
}
fn main(){println!("R67 offline guard; no original owner proof");}
