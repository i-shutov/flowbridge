//! R42 clean-room user-mode specification model, std-only, NO drivers / WFP / networking.
//! This is NOT a working Windows proof and has no source of trusted kernel events.
//! A production use would require independently proven, authenticated events.
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Family { V4, V6 }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Owner {
    pub pid: u64,
    pub creation_epoch: u64,
    pub process_start_key: u64,
    pub canonical_exe_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    pub session: u64,
    pub issuance: u64,
    pub owner: Owner,
    pub endpoint: u64,
    pub family: Family,
    pub tuple_fingerprint: u64, // comparison only; NEVER origin identity
}
impl Ticket {
    fn valid(&self) -> bool {
        self.session != 0 && self.issuance != 0 && self.endpoint != 0
            && self.owner.pid != 0 && self.owner.creation_epoch != 0
            && self.owner.process_start_key != 0 && self.owner.canonical_exe_id != 0
    }
    fn id(&self) -> (u64, u64) { (self.session, self.issuance) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State { Issued, Claimed, Revoked }

/// Hypothetical proof-bearing event ingress: caller must independently validate
/// the event's kernel origin. This model deliberately does not implement it.
#[derive(Default)]
pub struct Gate {
    tickets: BTreeMap<(u64,u64), (Ticket, State)>,
    dead_owners: BTreeSet<Owner>,
    terminated: bool,
}
impl Gate {
    pub fn issue(&mut self, ticket: Ticket) -> bool {
        if self.terminated || !ticket.valid() || self.dead_owners.contains(&ticket.owner)
            || self.tickets.contains_key(&ticket.id()) { return false; }
        self.tickets.insert(ticket.id(), (ticket, State::Issued));
        true
    }
    pub fn claim(&mut self, ticket: Ticket) -> bool {
        if self.terminated || self.dead_owners.contains(&ticket.owner) { return false; }
        let Some((original, state)) = self.tickets.get_mut(&ticket.id()) else { return false; };
        if *original != ticket || *state != State::Issued { return false; }
        *state = State::Claimed;
        true
    }
    pub fn origin_exited(&mut self, exact_owner: Owner) -> usize {
        self.dead_owners.insert(exact_owner);
        let mut count=0;
        for (ticket, state) in self.tickets.values_mut() {
            if ticket.owner == exact_owner && *state != State::Revoked {
                *state = State::Revoked;
                count += 1;
            }
        }
        count
    }
    pub fn health_lost(&mut self) {
        self.terminated = true;
        for (_, state) in self.tickets.values_mut() { *state = State::Revoked; }
    }
    /// Invoke immediately before every *model* release; no cached permit.
    /// This still cannot stop bytes already queued by the OS.
    pub fn may_release_now(&self, ticket: Ticket) -> bool {
        !self.terminated && !self.dead_owners.contains(&ticket.owner)
        && matches!(self.tickets.get(&ticket.id()), Some((actual, State::Claimed)) if *actual == ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> Owner { Owner { pid: 41, creation_epoch: 7, process_start_key: 99, canonical_exe_id: 32 } }
    fn t(f: Family) -> Ticket { Ticket { session: 5, issuance: 1, owner: owner(), endpoint: 19, family:f, tuple_fingerprint: 222 } }
    #[test] fn both_families_revoke_after_claim() {
        for f in [Family::V4, Family::V6] { let mut g=Gate::default(); let a=t(f); assert!(g.issue(a)); assert!(g.claim(a)); assert!(g.may_release_now(a)); assert_eq!(g.origin_exited(owner()),1); assert!(!g.may_release_now(a)); }
    }
    #[test] fn exit_before_claim_is_terminal() { let mut g=Gate::default();let a=t(Family::V4); assert!(g.issue(a));g.origin_exited(a.owner);assert!(!g.claim(a));assert!(!g.may_release_now(a)); }
    #[test] fn exit_before_issue_is_terminal() {let mut g=Gate::default();let a=t(Family::V6);g.origin_exited(a.owner);assert!(!g.issue(a)); }
    #[test] fn pid_reuse_and_identical_tuple_do_not_restore_old_ticket() {
        let mut g=Gate::default();let a=t(Family::V4);assert!(g.issue(a));assert!(g.claim(a));g.origin_exited(a.owner);
        let mut b=a; b.issuance=2;b.owner.creation_epoch=8; b.owner.process_start_key=100;
        assert_eq!(b.owner.pid,a.owner.pid);assert_eq!(b.tuple_fingerprint,a.tuple_fingerprint);
        assert!(g.issue(b));assert!(g.claim(b));assert!(!g.may_release_now(a));assert!(g.may_release_now(b));
    }
    #[test] fn wrong_epoch_does_not_revoke() {let mut g=Gate::default();let a=t(Family::V4);assert!(g.issue(a));assert!(g.claim(a));let mut b=a.owner;b.creation_epoch+=1;assert_eq!(g.origin_exited(b),0);assert!(g.may_release_now(a));}
    #[test] fn wrong_exe_does_not_revoke() {let mut g=Gate::default();let a=t(Family::V4);assert!(g.issue(a));assert!(g.claim(a));let mut b=a.owner;b.canonical_exe_id+=1;assert_eq!(g.origin_exited(b),0);assert!(g.may_release_now(a));}
    #[test] fn sibling_flow_not_revoked() {let mut g=Gate::default();let a=t(Family::V4);let mut b=a;b.issuance=2;b.owner.pid=50;b.owner.creation_epoch=9;assert!(g.issue(a));assert!(g.issue(b));assert!(g.claim(a));assert!(g.claim(b));g.origin_exited(a.owner);assert!(!g.may_release_now(a));assert!(g.may_release_now(b));}
    #[test] fn all_tickets_of_owner_revoked() {let mut g=Gate::default();let a=t(Family::V4);let mut b=t(Family::V6);b.issuance=2;b.endpoint=20;assert!(g.issue(a));assert!(g.issue(b));assert!(g.claim(a));assert!(g.claim(b));assert_eq!(g.origin_exited(a.owner),2);assert!(!g.may_release_now(a));assert!(!g.may_release_now(b));}
    #[test] fn forged_context_cannot_claim() {let mut g=Gate::default();let a=t(Family::V4);assert!(g.issue(a));let mut forged=a;forged.endpoint+=1;assert!(!g.claim(forged));assert!(g.claim(a));}
    #[test] fn tuple5_collision_is_not_identity() {let mut g=Gate::default();let a=t(Family::V4);let mut b=a;b.issuance=2;b.endpoint=45;b.family=Family::V6;assert!(g.issue(a));assert!(g.issue(b));assert!(g.claim(a));assert!(g.claim(b));g.origin_exited(a.owner);assert!(!g.may_release_now(a));assert!(!g.may_release_now(b));}
    #[test] fn claims_are_one_shot_and_issuance_is_not_recyclable() {let mut g=Gate::default();let a=t(Family::V4);assert!(g.issue(a));assert!(g.claim(a));assert!(!g.claim(a));g.origin_exited(a.owner);assert!(!g.issue(a));}
    #[test] fn health_loss_latches_globally() {let mut g=Gate::default();let a=t(Family::V4);assert!(g.issue(a));assert!(g.claim(a));g.health_lost();assert!(!g.may_release_now(a));assert!(!g.issue(t(Family::V6)));assert!(!g.claim(a));}
    #[test] fn invalid_identity_and_reused_issuance_fail() {let mut g=Gate::default();let mut a=t(Family::V4);a.owner.creation_epoch=0;assert!(!g.issue(a));a.owner=owner();assert!(g.issue(a));let mut b=a;b.endpoint+=1;assert!(!g.issue(b));}
}
