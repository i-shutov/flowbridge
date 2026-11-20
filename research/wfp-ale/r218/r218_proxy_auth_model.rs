//! R218: pure-Rust, no-driver user-mode NEGATIVE model of original-AppId
//! scoped AUTH_CONNECT versus redirect-record-tagged SSH proxy egress.
//! Conditional hypothesis, not real WFP classify, traffic or kernel proof.
#![forbid(unsafe_code)]

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum App {Selected,Broker,Other}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Proto {Tcp,Udp}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Peer {LocalBroker,ExternalSsh,ExternalOther}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Verdict {NotScoped,Permit,Block}
#[derive(Clone,Copy)]
struct Flow {original:App,current:App,proto:Proto,peer:Peer,redirected:bool,
             reauthorize:bool,pid_ok:bool,ticket_ok:bool}

// policy_windows.rs installs AUTH filter original AppId=Selected, TCP, V4/V6.
fn auth_filter_matches(f:Flow)->bool {
    f.original==App::Selected && f.proto==Proto::Tcp
}
// R19 auth_check requires redirected, non-reauthorize, broker loopback,
// same-PID and same-origin one-use kernel ticket (folded into ticket_ok).
fn auth_decision(f:Flow)->Verdict {
    if !auth_filter_matches(f){return Verdict::NotScoped;}
    if f.redirected && !f.reauthorize && f.peer==Peer::LocalBroker
       && f.pid_ok && f.ticket_ok && f.current!=App::Other {
       Verdict::Permit
    } else {Verdict::Block}
}
fn original_leg()->Flow {Flow{original:App::Selected,current:App::Selected,
    proto:Proto::Tcp,peer:Peer::LocalBroker,redirected:true,reauthorize:false,
    pid_ok:true,ticket_ok:true}}
fn tagged_ssh()->Flow {Flow{original:App::Selected,current:App::Broker,
    proto:Proto::Tcp,peer:Peer::ExternalSsh,redirected:true,reauthorize:false,
    pid_ok:true,ticket_ok:false}}

#[cfg(test)] mod tests {
 use super::*;
 #[test] fn original_leg_can_permit(){assert_eq!(auth_decision(original_leg()),Verdict::Permit);}
 #[test] fn tagged_ssh_is_self_blocked_if_original_app_id_propagates(){
    assert!(auth_filter_matches(tagged_ssh()));
    assert_eq!(auth_decision(tagged_ssh()),Verdict::Block);
 }
 #[test] fn even_a_ticket_does_not_make_external_ssh_loopback(){
    let mut f=tagged_ssh();f.ticket_ok=true;
    assert_eq!(auth_decision(f),Verdict::Block);
 }
 #[test] fn untagged_broker_not_selected(){let mut f=tagged_ssh();
    f.original=App::Broker;assert_eq!(auth_decision(f),Verdict::NotScoped);}
 #[test] fn direct_selected_tcp_blocked_udp_out_of_scope(){let mut f=original_leg();
    f.peer=Peer::ExternalOther;f.redirected=false;f.ticket_ok=false;
    assert_eq!(auth_decision(f),Verdict::Block);f.proto=Proto::Udp;
    assert_eq!(auth_decision(f),Verdict::NotScoped);}
 #[test] fn reauthorization_and_dead_origin_block(){let mut f=original_leg();
    f.reauthorize=true;assert_eq!(auth_decision(f),Verdict::Block);
    f.reauthorize=false;f.ticket_ok=false;
    assert_eq!(auth_decision(f),Verdict::Block);}
}
