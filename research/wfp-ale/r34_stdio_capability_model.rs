//! R34 offline, no-network/no-Windows local capability contract. Not native proof.
#![forbid(unsafe_code)]
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum Family{V4,V6}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum Protocol{Tcp,Udp}
#[derive(Clone,Copy,Debug)] pub struct Flow{pub ticket:u64,pub family:Family,pub protocol:Protocol}
#[derive(Clone,Copy,Debug)] pub struct Pipe{pub ticket:u64,pub child:u64,pub generation:u64}
#[derive(Clone,Copy,Debug)] pub enum Peer{SocksNoAuth,PidSnapshot,OwnedPipe(Pipe)}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum Decision{Reject,LocalPeerOnly,ConditionalRelease}
pub struct Gate{flow:Flow,child:u64,generation:u64,claim:bool,wfp_live:bool,child_live:bool,remote_proof:bool}
impl Gate{
 pub fn new(flow:Flow,child:u64,generation:u64)->Self{
  Self{flow,child,generation,claim:false,wfp_live:true,child_live:true,remote_proof:false}
 }
 pub fn claim(&mut self){self.claim=true}
 pub fn lose_wfp(&mut self){self.wfp_live=false}
 pub fn lose_child(&mut self){self.child_live=false}
 /// The real OpenSSH -W API does NOT supply this witness. It is an assumption.
 pub fn hypothetical_remote_proof(&mut self){self.remote_proof=true}
 pub fn decide(&self,peer:Peer)->Decision{
  if self.flow.protocol!=Protocol::Tcp||self.flow.ticket==0||!self.claim||!self.wfp_live||!self.child_live{
   return Decision::Reject;
  }
  match peer{
   Peer::OwnedPipe(p) if p.ticket==self.flow.ticket&&p.child==self.child&&
    p.generation==self.generation&&p.child!=0&&p.generation!=0=>{
     if self.remote_proof{Decision::ConditionalRelease}else{Decision::LocalPeerOnly}
    },
   _=>Decision::Reject
  }
 }
}
#[cfg(test)] mod tests{
 use super::*;
 fn flow(family:Family)->Flow{Flow{ticket:31,family,protocol:Protocol::Tcp}}
 fn pipe()->Peer{Peer::OwnedPipe(Pipe{ticket:31,child:23,generation:9})}
 fn gate(family:Family)->Gate{let mut g=Gate::new(flow(family),23,9);g.claim();g}
 #[test] fn both_families_only_local(){for f in [Family::V4,Family::V6]{let g=gate(f);assert_eq!(g.decide(pipe()),Decision::LocalPeerOnly);}}
 #[test] fn remote_proof_explicitly_hypothetical(){let mut g=gate(Family::V4);g.hypothetical_remote_proof();assert_eq!(g.decide(pipe()),Decision::ConditionalRelease);}
 #[test] fn socks_and_pid_cannot_attest(){let mut g=gate(Family::V4);g.hypothetical_remote_proof();assert_eq!(g.decide(Peer::SocksNoAuth),Decision::Reject);assert_eq!(g.decide(Peer::PidSnapshot),Decision::Reject);}
 #[test] fn no_claim(){let mut g=Gate::new(flow(Family::V4),23,9);g.hypothetical_remote_proof();assert_eq!(g.decide(pipe()),Decision::Reject);}
 #[test] fn dead_ssh_or_wfp(){let mut g=gate(Family::V4);g.hypothetical_remote_proof();g.lose_child();assert_eq!(g.decide(pipe()),Decision::Reject);let mut g=gate(Family::V4);g.hypothetical_remote_proof();g.lose_wfp();assert_eq!(g.decide(pipe()),Decision::Reject);}
 #[test] fn child_restarted_pipe_reused(){let mut g=Gate::new(flow(Family::V4),23,10);g.claim();g.hypothetical_remote_proof();assert_eq!(g.decide(pipe()),Decision::Reject);}
 #[test] fn ticket_reused_tuple(){let mut g=Gate::new(Flow{ticket:32,..flow(Family::V6)},23,9);g.claim();g.hypothetical_remote_proof();assert_eq!(g.decide(pipe()),Decision::Reject);}
 #[test] fn udp_not_selected(){let mut g=Gate::new(Flow{protocol:Protocol::Udp,..flow(Family::V4)},23,9);g.claim();g.hypothetical_remote_proof();assert_eq!(g.decide(pipe()),Decision::Reject);}
}
