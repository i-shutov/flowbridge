//! R81 clean-room safe Rust USER-MODE state model (no FFI, WFP, sockets).
//! It models memory retention and cannot prove real WSAOVERLAPPED completion.
use std::collections::BTreeMap;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Completion{Success,Failed,Cancelled}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Decision{HoldPending,RejectLate,RejectFailed,CandidateOnly,UnknownOperation}
struct Request{socket_generation:u64,request_generation:u64,expired:bool,
               cancel_requested:bool,owned_output:Vec<u8>}
#[derive(Default)]
pub struct Escrow{next:u64,pending:BTreeMap<u64,Request>}
impl Escrow{
 pub fn issue(&mut self,socket_generation:u64,request_generation:u64,bytes:usize)->u64{
  assert!(bytes<=65536);self.next=self.next.checked_add(1).expect("op id overflow");
  let id=self.next;
  self.pending.insert(id,Request{socket_generation,request_generation,
       expired:false,cancel_requested:false,owned_output:vec![0u8;bytes]});id
 }
 pub fn timeout(&mut self,id:u64)->Decision{
  match self.pending.get_mut(&id){Some(r)=>{r.expired=true;Decision::HoldPending},
                                  None=>Decision::UnknownOperation}
 }
 pub fn request_cancel(&mut self,id:u64)->Decision{
  match self.pending.get_mut(&id){Some(r)=>{r.cancel_requested=true;Decision::HoldPending},
                                  None=>Decision::UnknownOperation}
 }
 pub fn pending(&self)->usize{self.pending.len()}
 pub fn bytes_held(&self)->usize{self.pending.values().map(|r|r.owned_output.len()).sum()}
 // The caller must supply independently verified terminal I/O completion;
 // neither timeout nor cancellation REQUEST is terminal evidence.
 pub fn complete(&mut self,id:u64,status:Completion,socket:u64,request:u64)->Decision{
  let Some(r)=self.pending.remove(&id)else{return Decision::UnknownOperation;};
  if r.expired||r.socket_generation!=socket||r.request_generation!=request{
   return Decision::RejectLate;
  }
  match status{Completion::Success=>Decision::CandidateOnly,
               Completion::Failed|Completion::Cancelled=>Decision::RejectFailed}
 }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum CloseAck{NotAttempted,Success,FailedOrLost}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum CloseEvidence{SessionOpenModeled,DynamicSessionEnded,Unknown}
pub fn close_evidence(owner_alive:bool,ack:CloseAck)->CloseEvidence{
 if !owner_alive||ack==CloseAck::Success{CloseEvidence::DynamicSessionEnded}
 else if ack==CloseAck::FailedOrLost{CloseEvidence::Unknown}
 else{CloseEvidence::SessionOpenModeled}
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn timeout_and_cancel_hold_simulated_memory(){
  let mut e=Escrow::default();let id=e.issue(1,1,32768);
  assert_eq!(e.timeout(id),Decision::HoldPending);
  assert_eq!(e.request_cancel(id),Decision::HoldPending);
  assert_eq!((e.pending(),e.bytes_held()),(1,32768));
  assert_eq!(e.complete(id,Completion::Success,1,1),Decision::RejectLate);
  assert_eq!(e.pending(),0);
 }
 #[test]fn failure_rejects(){
  for s in [Completion::Failed,Completion::Cancelled]{
   let mut e=Escrow::default();let id=e.issue(1,1,128);
   assert_eq!(e.complete(id,s,1,1),Decision::RejectFailed);
  }
 }
 #[test]fn socket_and_request_generation_differ(){
  for (s,r) in [(2,1),(1,2)]{
   let mut e=Escrow::default();let id=e.issue(1,1,0);
   assert_eq!(e.complete(id,Completion::Success,s,r),Decision::RejectLate);
  }
 }
 #[test]fn success_remains_candidate_only(){
  let mut e=Escrow::default();let id=e.issue(4,7,16);
  assert_eq!(e.complete(id,Completion::Success,4,7),Decision::CandidateOnly);
 }
 #[test]fn duplicate_completed_op_cannot_replay(){
  let mut e=Escrow::default();let id=e.issue(4,7,16);
  assert_eq!(e.complete(id,Completion::Success,4,7),Decision::CandidateOnly);
  assert_eq!(e.complete(id,Completion::Success,4,7),Decision::UnknownOperation);
 }
 #[test]fn pending_quarantine_consumes_capacity(){
  let mut e=Escrow::default();
  for _ in 0..32{let id=e.issue(4,7,1024);e.timeout(id);}
  assert_eq!((e.pending(),e.bytes_held()),(32,32768));
 }
 #[test]fn close_error_unknown(){
  assert_eq!(close_evidence(true,CloseAck::FailedOrLost),CloseEvidence::Unknown);
 }
 #[test]fn owner_death_invalidates_dynamic_session(){
  assert_eq!(close_evidence(false,CloseAck::NotAttempted),CloseEvidence::DynamicSessionEnded);
 }
}
