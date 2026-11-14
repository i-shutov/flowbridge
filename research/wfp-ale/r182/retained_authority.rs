//! R182: PURE USER-MODE MODEL of retained connection authority after one-use CLAIM.
//!
//! Independent clean-room Rust, no WDK imports, driver code, socket I/O,
//! BFE manipulation, product PacketBound, or native acceptance.
//! All Observation values are synthetic test inputs; this model cannot mint a
//! kernel proof. The actual producer MUST supply immutable OS-origin metadata.
//!
//! Fundamental rule: consuming a one-use CLAIM does NOT consume the separately
//! retained original authorization record. Reauthorization is continuity of an
//! already attested and attached flow, NEVER a fresh permission or new CLAIM.
use std::net::IpAddr;

pub const MAX_FLOWS: usize = 64;
pub const MAX_RECORD_BYTES: usize = 2048;
pub const MAX_REAUTHORIZE: u16 = 64;
pub const CLAIM_WINDOW: u64 = 100_000_000; // 10s in 100ns units (model)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family { V4, V6 }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub nonce: u128,
    pub policy_generation: u64,
    pub bfe_generation: u64,
    pub ssh_generation: u64,
}
impl Session {
    fn valid(&self) -> bool {
        self.nonce != 0 && self.policy_generation != 0 &&
        self.bfe_generation != 0 && self.ssh_generation != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub session: Session,
    pub transaction: u128,
    pub endpoint: u64,
    pub pid: u64,
    pub process_object: u64,
    pub file_object: u64,
    pub creation_epoch: u64,
    pub process_start_key: u64,
    /// Pinned canonical, complete AppId units (NOT a basename).
    pub appid_utf16: Vec<u16>,
    pub family: Family,
    pub original_ip: IpAddr,
    pub original_port: u16,
    pub compartment: u32,
}
impl Binding {
    pub fn valid(&self) -> bool {
        let family_ok = matches!((self.family, self.original_ip),
            (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_)));
        family_ok && self.session.valid() && self.transaction != 0 &&
            self.endpoint != 0 && self.pid != 0 && self.process_object != 0 &&
            self.file_object != 0 && self.creation_epoch != 0 &&
            self.process_start_key != 0 && self.original_port != 0 &&
            self.compartement_valid() &&
            !self.original_ip.is_unspecified() &&
            !self.original_ip.is_multicast() &&
            !self.original_ip.is_loopback() &&
            (1..=256).contains(&self.appid_utf16.len()) &&
            self.appid_utf16.iter().all(|x| *x != 0)
    }
    fn compartement_valid(&self) -> bool { self.compartment != 0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction { Outbound, Reverse }

#[derive(Clone, Debug)]
pub struct Observation {
    pub binding: Binding,
    /// The caller MUST obtain these fields from one genuine WFP classify,
    /// not a user-mode PID lookup; booleans are synthetic in this model.
    pub full_kernel_metadata: bool,
    pub original_appid: Vec<u16>,
    pub redirected_flag: bool,
    pub original_destination_attested: bool,
    pub can_write_action: bool,
    pub reauthorize_flag: bool,
    pub honoring_policy_authorize: bool,
    pub direction: Direction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage { Redirected, InitialAuth, Claimed, EgressAttached, Revoked }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    Invalid, NoFlow, SessionLost, Capacity, EndpointReused,
    IdentityMismatch, UntrustedMetadata, WrongPhase, NoActionWrite,
    Replay, MissingRecords, MissingEgressAttach, PolicyChanged,
    ClockReversed, Expired, ReauthorizeBudget,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Only a modeled initial authorization; NOT a kernel WFP PERMIT.
    InitialAuthAccepted,
    /// One-use claim; never a network/driver authorization.
    ClaimAccepted,
    /// Synthetic proof that record bytes match a pre-connect attach.
    EgressAttachAccepted,
    /// ONLY continuity of a previously attached flow, NOT a new PERMIT.
    ContinueExisting,
    Denied(Denial),
}

#[derive(Clone, Debug)]
struct Entry {
    binding: Binding,
    stage: Stage,
    issued_at: u64,
    claim_records: Vec<u8>,
    reauth_count: u16,
}

pub struct Authority {
    session: Session,
    last_clock: u64,
    closed: bool,
    entries: Vec<Entry>,
}
impl Authority {
    pub fn new(session: Session) -> Result<Self, Denial> {
        if !session.valid() { return Err(Denial::Invalid); }
        Ok(Self {session, last_clock: 0, closed: false, entries: Vec::new()})
    }
    pub fn halted(&self) -> bool { self.closed }
    pub fn size(&self) -> usize { self.entries.len() }
    pub fn stage(&self, transaction: u128) -> Option<Stage> {
        self.entries.iter().find(|e|e.binding.transaction==transaction).map(|e|e.stage)
    }
    fn revoke_all(&mut self) {
        self.closed = true;
        for entry in &mut self.entries { entry.stage = Stage::Revoked; }
    }
    fn tick(&mut self, now: u64) -> Result<(), Denial> {
        if self.closed {return Err(Denial::SessionLost);}
        if now==0 {self.revoke_all();return Err(Denial::Invalid);}
        if now<self.last_clock {self.revoke_all();return Err(Denial::ClockReversed);}
        self.last_clock = now;
        Ok(())
    }
    /// BFE/SSH loss, owner exit or generation change terminates *all*
    /// retained authority. No same-session re-ARM or recovered permit.
    pub fn revoke_session(&mut self) {self.revoke_all();}
    pub fn redirect(&mut self, binding: Binding, now:u64) -> Result<(),Denial> {
        self.tick(now)?;
        if binding.session != self.session || !binding.valid() {
            return Err(Denial::Invalid);
        }
        if self.entries.iter().any(|e| e.binding.endpoint==binding.endpoint
                                    || e.binding.transaction==binding.transaction) {
            self.revoke_all();
            return Err(Denial::EndpointReused);
        }
        if self.entries.len()==MAX_FLOWS {
            self.revoke_all();
            return Err(Denial::Capacity);
        }
        self.entries.push(Entry {binding,stage:Stage::Redirected,issued_at:now,
                                 claim_records:Vec::new(),reauth_count:0});
        Ok(())
    }
    fn lookup(&mut self, binding:&Binding) -> Result<usize,Denial> {
        if self.closed {return Err(Denial::SessionLost);}
        if binding.session != self.session {
            self.revoke_all();return Err(Denial::PolicyChanged);
        }
        let Some(i) = self.entries.iter().position(|e|e.binding.transaction==binding.transaction)
            else {return Err(Denial::NoFlow)};
        if self.entries[i].binding != *binding {
            self.entries[i].stage = Stage::Revoked;
            return Err(Denial::IdentityMismatch);
        }
        if self.entries[i].stage==Stage::Revoked {return Err(Denial::SessionLost);}
        Ok(i)
    }
    fn check_observation(&mut self, obs:&Observation) -> Result<usize,Denial> {
        let i=self.lookup(&obs.binding)?;
        if !obs.full_kernel_metadata || !obs.original_destination_attested ||
           !obs.redirected_flag || obs.original_appid != obs.binding.appid_utf16 {
            self.entries[i].stage=Stage::Revoked;
            return Err(Denial::UntrustedMetadata);
        }
        if !obs.can_write_action {
            // Caller must preserve WFP arbitration; this returns no PERMIT.
            self.entries[i].stage=Stage::Revoked;
            return Err(Denial::NoActionWrite);
        }
        Ok(i)
    }
    pub fn initial_auth(&mut self, obs:&Observation, now:u64) -> Outcome {
        if let Err(e)=self.tick(now) {return Outcome::Denied(e);}
        let i=match self.check_observation(obs) {Ok(i)=>i,Err(e)=>return Outcome::Denied(e)};
        if obs.reauthorize_flag || obs.honoring_policy_authorize ||
           obs.direction != Direction::Outbound {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::WrongPhase);
        }
        if self.entries[i].stage!=Stage::Redirected {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::Replay);
        }
        if now.saturating_sub(self.entries[i].issued_at)>CLAIM_WINDOW {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::Expired);
        }
        self.entries[i].stage=Stage::InitialAuth;
        Outcome::InitialAuthAccepted
    }
    /// Records are opaque Winsock bytes supplied by a *separate trusted*
    /// accepted-socket observer. Their bytes are stored for equality, not
    /// treated as authenticity or a self-supplied security capability.
    pub fn claim(&mut self,binding:&Binding,records:&[u8],context_transaction:u128,
                 accepted_socket_attested:bool,now:u64) -> Outcome {
        if let Err(e)=self.tick(now) {return Outcome::Denied(e);}
        let i=match self.lookup(binding) {Ok(i)=>i,Err(e)=>return Outcome::Denied(e)};
        if self.entries[i].stage!=Stage::InitialAuth {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::Replay);
        }
        if now.saturating_sub(self.entries[i].issued_at)>CLAIM_WINDOW {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::Expired);
        }
        if !accepted_socket_attested || context_transaction!=binding.transaction ||
           records.is_empty() || records.len()>MAX_RECORD_BYTES {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::MissingRecords);
        }
        self.entries[i].claim_records=records.to_vec();
        self.entries[i].stage=Stage::Claimed;
        Outcome::ClaimAccepted
    }
    /// The caller must prove a real SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS
    /// on the actual outgoing socket *before* connect. Here only bytes and
    /// modeled ordering are tested.
    pub fn preconnect_attach(&mut self,binding:&Binding,records:&[u8],
                  preconnect:bool,set_records_succeeded:bool,now:u64) -> Outcome {
        if let Err(e)=self.tick(now) {return Outcome::Denied(e);}
        let i=match self.lookup(binding) {Ok(i)=>i,Err(e)=>return Outcome::Denied(e)};
        if self.entries[i].stage!=Stage::Claimed {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::WrongPhase);
        }
        if !preconnect || !set_records_succeeded ||
           self.entries[i].claim_records != records {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::MissingEgressAttach);
        }
        self.entries[i].stage=Stage::EgressAttached;
        Outcome::EgressAttachAccepted
    }
    pub fn reauthorize(&mut self,obs:&Observation,now:u64) -> Outcome {
        if let Err(e)=self.tick(now) {return Outcome::Denied(e);}
        let i=match self.check_observation(obs) {Ok(i)=>i,Err(e)=>return Outcome::Denied(e)};
        if !obs.reauthorize_flag {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::WrongPhase);
        }
        // HONORING_POLICY_AUTHORIZE and reverse-direction reclassification
        // require *all* original authority fields. Never infer FWP_EMPTY.
        if self.entries[i].stage!=Stage::EgressAttached {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::MissingEgressAttach);
        }
        if self.entries[i].reauth_count==MAX_REAUTHORIZE {
            self.entries[i].stage=Stage::Revoked;
            return Outcome::Denied(Denial::ReauthorizeBudget);
        }
        self.entries[i].reauth_count+=1;
        Outcome::ContinueExisting
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr,Ipv6Addr};
    fn session()->Session{Session{nonce:12,policy_generation:3,bfe_generation:4,ssh_generation:5}}
    fn binding(family:Family)->Binding{
        Binding{session:session(),transaction:10,endpoint:11,pid:42,process_object:44,
        file_object:45,creation_epoch:46,process_start_key:47,
        appid_utf16:"\\device\\harddiskvolume3\\app.exe".encode_utf16().collect(),
        family,original_ip:match family{Family::V4=>IpAddr::V4(Ipv4Addr::new(203,0,113,2)),
        Family::V6=>IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap())},
        original_port:443,compartment:1}
    }
    fn obs(b:&Binding,reauth:bool,dir:Direction)->Observation {
        Observation{binding:b.clone(),full_kernel_metadata:true,original_appid:b.appid_utf16.clone(),
        redirected_flag:true,original_destination_attested:true,can_write_action:true,
        reauthorize_flag:reauth,honoring_policy_authorize:false,direction:dir}
    }
    fn new()->Authority{Authority::new(session()).unwrap()}
    fn ready(family:Family)->(Authority,Binding){
        let b=binding(family);let mut a=new();
        a.redirect(b.clone(),1).unwrap();
        assert_eq!(a.initial_auth(&obs(&b,false,Direction::Outbound),2),Outcome::InitialAuthAccepted);
        assert_eq!(a.claim(&b,b"opaque",b.transaction,true,3),Outcome::ClaimAccepted);
        assert_eq!(a.preconnect_attach(&b,b"opaque",true,true,4),Outcome::EgressAttachAccepted);
        (a,b)
    }
    #[test]fn retained_continuity_ipv4_ipv6_and_reverse(){
        for f in [Family::V4,Family::V6]{
            let (mut a,b)=ready(f);
            for dir in [Direction::Outbound,Direction::Reverse]{
                assert_eq!(a.reauthorize(&obs(&b,true,dir),5),Outcome::ContinueExisting);
                assert_eq!(a.stage(b.transaction),Some(Stage::EgressAttached));
            }
        }
    }
    #[test]fn honoring_policy_authorize_still_needs_full_binding(){
        let (mut a,b)=ready(Family::V4);let mut o=obs(&b,true,Direction::Reverse);
        o.honoring_policy_authorize=true;
        assert_eq!(a.reauthorize(&o,10),Outcome::ContinueExisting);
    }
    #[test]fn reauth_before_claim_or_egress_is_not_permitted(){
        for state in [0,1,2]{
            let b=binding(Family::V4);let mut a=new();a.redirect(b.clone(),1).unwrap();
            if state>=1{assert_eq!(a.initial_auth(&obs(&b,false,Direction::Outbound),2),Outcome::InitialAuthAccepted);}
            if state>=2{assert_eq!(a.claim(&b,b"x",b.transaction,true,3),Outcome::ClaimAccepted);}
            assert_eq!(a.reauthorize(&obs(&b,true,Direction::Outbound),4),Outcome::Denied(Denial::MissingEgressAttach));
            assert_eq!(a.stage(b.transaction),Some(Stage::Revoked));
        }
    }
    #[test]fn reauth_with_absent_original_appid_revokes(){
        let (mut a,b)=ready(Family::V4);let mut o=obs(&b,true,Direction::Reverse);
        o.original_appid.clear();
        assert_eq!(a.reauthorize(&o,6),Outcome::Denied(Denial::UntrustedMetadata));
    }
    #[test]fn reauth_with_empty_fwps_metadata_revokes(){
        let (mut a,b)=ready(Family::V4);let mut o=obs(&b,true,Direction::Reverse);
        o.full_kernel_metadata=false;
        assert_eq!(a.reauthorize(&o,6),Outcome::Denied(Denial::UntrustedMetadata));
    }
    #[test]fn original_destination_mismatch_revokes(){
        let (mut a,b)=ready(Family::V6);let mut x=b.clone();x.original_port+=1;
        assert_eq!(a.reauthorize(&obs(&x,true,Direction::Outbound),8),Outcome::Denied(Denial::IdentityMismatch));
    }
    #[test]fn compartment_change_is_not_continuity(){
        let (mut a,b)=ready(Family::V4);let mut x=b.clone();x.compartment+=1;
        assert_eq!(a.reauthorize(&obs(&x,true,Direction::Outbound),8),Outcome::Denied(Denial::IdentityMismatch));
    }
    #[test]fn pid_reuse_even_with_same_appid_revokes(){
        let (mut a,b)=ready(Family::V4);let mut x=b.clone();x.creation_epoch+=1;
        assert_eq!(a.reauthorize(&obs(&x,true,Direction::Outbound),8),Outcome::Denied(Denial::IdentityMismatch));
    }
    #[test]fn process_start_key_and_object_mismatch_revoke(){
        for n in 0..3{
            let (mut a,b)=ready(Family::V4);let mut x=b.clone();
            match n{0=>x.process_start_key+=1,1=>x.process_object+=1,_=>x.file_object+=1}
            assert_eq!(a.reauthorize(&obs(&x,true,Direction::Outbound),8),Outcome::Denied(Denial::IdentityMismatch));
        }
    }
    #[test]fn policy_bfe_ssh_generation_mismatch_halts(){
        for n in 0..3{
            let (mut a,b)=ready(Family::V4);let mut x=b.clone();
            match n{0=>x.session.policy_generation+=1,
                    1=>x.session.bfe_generation+=1,
                    _=>x.session.ssh_generation+=1}
            assert_eq!(a.reauthorize(&obs(&x,true,Direction::Outbound),8),Outcome::Denied(Denial::PolicyChanged));
            assert!(a.halted());
        }
    }
    #[test]fn bfe_ssh_loss_revokes_and_cannot_rearm(){
        let (mut a,b)=ready(Family::V4);a.revoke_session();
        assert_eq!(a.reauthorize(&obs(&b,true,Direction::Reverse),10),Outcome::Denied(Denial::SessionLost));
        assert_eq!(a.redirect(b,11),Err(Denial::SessionLost));
    }
    #[test]fn no_action_write_does_not_issue_permit(){
        let (mut a,b)=ready(Family::V4);let mut o=obs(&b,true,Direction::Outbound);
        o.can_write_action=false;
        assert_eq!(a.reauthorize(&o,6),Outcome::Denied(Denial::NoActionWrite));
    }
    #[test]fn replay_initial_and_claim_denied(){
        let b=binding(Family::V4);let mut a=new();a.redirect(b.clone(),1).unwrap();
        assert_eq!(a.initial_auth(&obs(&b,false,Direction::Outbound),2),Outcome::InitialAuthAccepted);
        assert_eq!(a.initial_auth(&obs(&b,false,Direction::Outbound),3),Outcome::Denied(Denial::Replay));
        let (mut a,b)=ready(Family::V4);
        assert_eq!(a.claim(&b,b"opaque",b.transaction,true,10),Outcome::Denied(Denial::Replay));
    }
    #[test]fn different_redirect_records_cannot_be_attached(){
        let b=binding(Family::V4);let mut a=new();a.redirect(b.clone(),1).unwrap();
        a.initial_auth(&obs(&b,false,Direction::Outbound),2);
        a.claim(&b,b"opaque",b.transaction,true,3);
        assert_eq!(a.preconnect_attach(&b,b"altered",true,true,4),Outcome::Denied(Denial::MissingEgressAttach));
    }
    #[test]fn post_connect_redirect_records_cannot_be_attached(){
        let b=binding(Family::V4);let mut a=new();a.redirect(b.clone(),1).unwrap();
        a.initial_auth(&obs(&b,false,Direction::Outbound),2);
        a.claim(&b,b"opaque",b.transaction,true,3);
        assert_eq!(a.preconnect_attach(&b,b"opaque",false,true,4),Outcome::Denied(Denial::MissingEgressAttach));
    }
    #[test]fn no_accepted_socket_or_context_cannot_claim(){
        let b=binding(Family::V4);let mut a=new();a.redirect(b.clone(),1).unwrap();
        a.initial_auth(&obs(&b,false,Direction::Outbound),2);
        assert_eq!(a.claim(&b,b"opaque",b.transaction,false,3),Outcome::Denied(Denial::MissingRecords));
    }
    #[test]fn reused_endpoint_poisoned_even_with_new_transaction(){
        let b=binding(Family::V4);let mut a=new();a.redirect(b.clone(),1).unwrap();
        let mut next=b;next.transaction+=1;
        assert_eq!(a.redirect(next,2),Err(Denial::EndpointReused));assert!(a.halted());
    }
    #[test]fn sibling_direct_cannot_be_upgraded_by_foreign_tx(){
        let (mut a,b)=ready(Family::V4);let mut x=b.clone();x.transaction=999;
        assert_eq!(a.reauthorize(&obs(&x,true,Direction::Outbound),6),Outcome::Denied(Denial::NoFlow));
        assert_eq!(a.stage(b.transaction),Some(Stage::EgressAttached));
    }
    #[test]fn no_initial_reauth_or_reverse_first_authorization(){
        for reauth in [true,false]{
            let b=binding(Family::V4);let mut a=new();a.redirect(b.clone(),1).unwrap();
            let result=a.initial_auth(&obs(&b,reauth,Direction::Reverse),2);
            assert_eq!(result,Outcome::Denied(Denial::WrongPhase));
        }
    }
    #[test]fn missing_reauth_flag_not_relabelled(){
        let (mut a,b)=ready(Family::V4);
        assert_eq!(a.reauthorize(&obs(&b,false,Direction::Reverse),6),Outcome::Denied(Denial::WrongPhase));
    }
    #[test]fn monotonic_clock_rewind_is_terminal(){
        let (mut a,b)=ready(Family::V4);
        assert_eq!(a.reauthorize(&obs(&b,true,Direction::Reverse),3),Outcome::Denied(Denial::ClockReversed));
        assert!(a.halted());
    }
    #[test]fn claim_timeout_refuses_late_receipt(){
        let b=binding(Family::V4);let mut a=new();a.redirect(b.clone(),1).unwrap();
        a.initial_auth(&obs(&b,false,Direction::Outbound),2);
        assert_eq!(a.claim(&b,b"opaque",b.transaction,true,CLAIM_WINDOW+2),Outcome::Denied(Denial::Expired));
    }
    #[test]fn reauth_budget_never_wraps(){
        let (mut a,b)=ready(Family::V6);
        for i in 0..MAX_REAUTHORIZE {
            assert_eq!(a.reauthorize(&obs(&b,true,Direction::Reverse),i as u64+5),Outcome::ContinueExisting);
        }
        assert_eq!(a.reauthorize(&obs(&b,true,Direction::Reverse),100),Outcome::Denied(Denial::ReauthorizeBudget));
    }
    #[test]fn invalid_missing_pid_ip_or_protocol_denied(){
        for n in 0..5{
            let mut b=binding(Family::V4);
            match n{0=>b.pid=0,1=>b.original_port=0,
                    2=>b.original_ip=IpAddr::V4(Ipv4Addr::LOCALHOST),
                    3=>b.family=Family::V6,_=>b.appid_utf16=vec![0]}
            assert_eq!(new().redirect(b,1),Err(Denial::Invalid));
        }
    }
    #[test]fn flow_capacity_is_bounded_and_never_evicts(){
        let mut a=new();
        for i in 0..MAX_FLOWS{
            let mut b=binding(Family::V4);b.transaction+=i as u128;b.endpoint+=i as u64;
            a.redirect(b,1).unwrap();
        }
        let mut extra=binding(Family::V4);extra.transaction=1000;extra.endpoint=1000;
        assert_eq!(a.redirect(extra,2),Err(Denial::Capacity));
        assert!(a.halted());
        assert_eq!(a.size(),MAX_FLOWS);
    }
    #[test]fn new_invalid_session_cannot_arm(){
        let mut s=session();s.nonce=0;
        assert!(matches!(Authority::new(s),Err(Denial::Invalid)));
    }
}
