//! R201 clean-room USER-MODE MODEL. No WFP, drivers, FFI, sockets, network, or OS handles.
//! Opaque reference values stand for evidence a future kernel implementation must obtain.
//! The model tests identity/lifetime invariants, NOT authenticity of those values.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub pid: u64,
    pub epoch: u64,
    pub start_key: u64,
    pub process_ref: u64,
    pub file_ref: u64,
    pub canonical_exe: String,
}
impl Identity {
    fn complete(&self) -> bool {
        self.pid != 0 && self.epoch != 0 && self.start_key != 0
            && self.process_ref != 0 && self.file_ref != 0
            && !self.canonical_exe.is_empty()
    }
    fn incarnation(&self) -> (u64, u64, u64) {
        (self.pid, self.epoch, self.start_key)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { Selected, Broker }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision { Ignored, Accepted, Denied, Stopped }
#[derive(Clone, Debug)]
struct Tracked { identity: Identity, role: Role, generation: u64 }
#[derive(Clone, Debug)]
struct Ticket {
    identity: (u64, u64, u64),
    generation: u64,
    endpoint: u64,
    family: u8,
    destination: String,
    attested: bool,
}

/// Paths must be pinned before observing ANY process creation. This is a
/// prerequisite to be proven separately, NOT an available R19 bootstrap.
#[derive(Clone, Debug)]
pub struct Pins { pub selected: String, pub broker: String }
impl Pins {
    pub fn new(selected: &str, broker: &str) -> Option<Self> {
        if selected.is_empty() || broker.is_empty() || selected == broker {return None;}
        Some(Self {selected: selected.into(), broker: broker.into()})
    }
    fn role(&self, exe: &str) -> Option<Role> {
        if exe == self.selected {Some(Role::Selected)}
        else if exe == self.broker {Some(Role::Broker)} else {None}
    }
}

/// Fixed budgets bound memory; hitting a trust-critical budget stops the session.
/// Live slots are reclaimed ONLY on matching process-object exit; stale tickets
/// retain an incarnation/generation and cannot match newly created processes.
pub struct SelectiveLedger {
    pins: Pins,
    live: Vec<Tracked>,
    history: Vec<(u64, u64, u64)>,
    endpoints: Vec<u64>,
    tickets: Vec<Ticket>,
    next_generation: u64,
    max_live: usize,
    max_history: usize,
    max_endpoints: usize,
    pub stopped: bool,
}
impl SelectiveLedger {
    pub fn new(pins: Pins, max_live: usize, max_history: usize, max_endpoints: usize) -> Self {
        Self {pins, live: vec![], history: vec![], endpoints: vec![], tickets: vec![],
            next_generation: 0, max_live, max_history, max_endpoints, stopped: false}
    }
    fn stop(&mut self) -> Decision {
        self.stopped = true;
        self.tickets.clear();
        Decision::Stopped
    }
    pub fn health_lost(&mut self) { self.stop(); }
    pub fn live_count(&self) -> usize {self.live.len()}
    pub fn history_count(&self) -> usize {self.history.len()}

    pub fn born(&mut self, id: Identity) -> Decision {
        if self.stopped {return Decision::Stopped;}
        // Unrelated births do not use selected/broker storage. A collision with
        // an active tracked PID is anomalous even if the new EXE is unrelated.
        if self.live.iter().any(|x|x.identity.pid == id.pid) {return self.stop();}
        let Some(role) = self.pins.role(&id.canonical_exe) else {return Decision::Ignored;};
        if !id.complete() || self.live.len() == self.max_live
            || self.history.len() == self.max_history
            || self.history.contains(&id.incarnation()) {
            return self.stop();
        }
        let Some(generation) = self.next_generation.checked_add(1) else {return self.stop();};
        self.next_generation = generation;
        self.history.push(id.incarnation());
        self.live.push(Tracked {identity: id, role, generation});
        Decision::Accepted
    }
    pub fn died(&mut self, pid: u64, process_ref: u64) -> Decision {
        if self.stopped {return Decision::Stopped;}
        let Some(index) = self.live.iter().position(|x|x.identity.pid == pid) else {
            return Decision::Ignored;
        };
        if self.live[index].identity.process_ref != process_ref {return self.stop();}
        let departed = self.live.remove(index);
        self.tickets.retain(|t| !(t.identity == departed.identity.incarnation()
            && t.generation == departed.generation));
        if departed.role == Role::Broker {return self.stop();}
        Decision::Accepted
    }
    pub fn issue(&mut self, id: &Identity, endpoint: u64, family: u8,
                 protocol: u8, destination: &str) -> Decision {
        if self.stopped {return Decision::Stopped;}
        if endpoint == 0 || !matches!(family, 4 | 6) || protocol != 6
            || destination.is_empty() {return Decision::Denied;}
        // Identity gate BEFORE tombstone handling: an untracked sibling cannot
        // consume or poison selected endpoint history through this interface.
        let Some(owner) = self.live.iter().find(|x|x.role == Role::Selected && x.identity == *id) else {
            return Decision::Denied;
        };
        let generation = owner.generation;
        if !self.live.iter().any(|x|x.role == Role::Broker) {return Decision::Denied;}
        if self.endpoints.contains(&endpoint) || self.endpoints.len() == self.max_endpoints {
            return self.stop(); // ABA or bounded endpoint memory exhaustion
        }
        self.tickets.push(Ticket {identity: id.incarnation(), generation,
            endpoint, family, destination: destination.into(), attested: false});
        self.endpoints.push(endpoint);
        Decision::Accepted
    }
    /// Caller asserts a same-kernel-classify observation; the model cannot
    /// independently prove this was actually a FWPS ALE_AUTH_CONNECT indication.
    pub fn attest(&mut self, id: &Identity, endpoint: u64, family: u8,
                  original_destination: &str, original_appid: &str,
                  redirected: bool, reauthorize: bool) -> Decision {
        if self.stopped {return Decision::Stopped;}
        if !redirected || reauthorize || original_appid != self.pins.selected {return Decision::Denied;}
        let Some(owner) = self.live.iter().find(|x|x.role == Role::Selected && x.identity == *id) else {
            return Decision::Denied;
        };
        let Some(ticket) = self.tickets.iter_mut().find(|t| t.identity == id.incarnation()
            && t.generation == owner.generation && t.endpoint == endpoint
            && t.family == family && t.destination == original_destination && !t.attested) else {
            return Decision::Denied;
        };
        ticket.attested = true;
        Decision::Accepted
    }
    /// A semantic one-use claim; NOT a binding to an accepted Winsock socket.
    pub fn claim(&mut self, id: &Identity, endpoint: u64) -> Decision {
        if self.stopped {return Decision::Stopped;}
        let Some(idx) = self.tickets.iter().position(|t|t.endpoint == endpoint) else {return Decision::Denied;};
        let t = self.tickets.remove(idx); // terminal even for failed claims
        let valid_live = self.live.iter().any(|x|x.role == Role::Selected
            && x.identity == *id && x.identity.incarnation() == t.identity
            && x.generation == t.generation);
        if t.attested && valid_live {Decision::Accepted} else {Decision::Denied}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SEL: &str = r"\device\volume1\selected.exe";
    const BRK: &str = r"\device\volume1\broker.exe";
    fn owner(pid: u64, exe: &str) -> Identity {
        Identity {pid, epoch: pid + 100, start_key: pid + 900,
            process_ref: pid + 1, file_ref: pid + 2, canonical_exe: exe.into()}
    }
    fn ledger() -> SelectiveLedger {SelectiveLedger::new(Pins::new(SEL,BRK).unwrap(), 4, 32, 32)}
    fn flow(l: &mut SelectiveLedger, id: &Identity, ep: u64) -> Decision {
        assert_eq!(l.issue(id,ep,4,6,"198.51.100.2:443"),Decision::Accepted);
        l.attest(id,ep,4,"198.51.100.2:443",SEL,true,false)
    }
    #[test]fn unrelated_churn_does_not_consume_slots() {
        let mut l=ledger();l.born(owner(1,SEL));l.born(owner(2,BRK));
        for i in 100..10_100 {assert_eq!(l.born(owner(i,"other")),Decision::Ignored);l.died(i,i+1);}
        assert_eq!(l.live_count(),2);assert_eq!(l.history_count(),2);assert!(!l.stopped);
    }
    #[test]fn exact_object_exit_and_pid_reuse_reclaims_only_live_slot() {
        let mut l=ledger();let a=owner(1,SEL);l.born(a.clone());
        assert_eq!(l.died(1,a.process_ref),Decision::Accepted);
        let mut b=a.clone();b.epoch+=1;b.start_key+=1;b.process_ref+=10;
        assert_eq!(l.born(b),Decision::Accepted);assert_eq!(l.live_count(),1);
        assert_eq!(l.born(a),Decision::Stopped); // stale old incarnation cannot reappear
    }
    #[test]fn wrong_exit_object_and_live_pid_collision_stop() {
        let mut l=ledger();l.born(owner(1,SEL));assert_eq!(l.died(1,999),Decision::Stopped);
        let mut l=ledger();l.born(owner(1,SEL));
        assert_eq!(l.born(owner(1,"other")),Decision::Stopped);
    }
    #[test]fn reusing_five_tuple_has_no_authority() {
        let mut l=ledger();let a=owner(1,SEL);l.born(a.clone());l.born(owner(2,BRK));
        assert_eq!(flow(&mut l,&a,91),Decision::Accepted);
        l.died(1,a.process_ref);
        let mut b=a.clone();b.epoch+=1;b.start_key+=1;b.process_ref+=1;
        assert_eq!(l.born(b.clone()),Decision::Accepted);
        assert_eq!(l.claim(&a,91),Decision::Denied);
        assert_eq!(flow(&mut l,&b,92),Decision::Accepted);
        assert_eq!(l.claim(&b,92),Decision::Accepted);
        assert_eq!(l.claim(&b,92),Decision::Denied);
    }
    #[test]fn endpoint_aba_is_terminal_even_after_success() {
        let mut l=ledger();let a=owner(1,SEL);l.born(a.clone());l.born(owner(2,BRK));
        assert_eq!(flow(&mut l,&a,91),Decision::Accepted);
        assert_eq!(l.claim(&a,91),Decision::Accepted);
        assert_eq!(l.issue(&a,91,4,6,"198.51.100.2:443"),Decision::Stopped);
    }
    #[test]fn no_broker_birth_prevents_issue() {
        let mut l=ledger();let a=owner(1,SEL);l.born(a.clone());
        assert_eq!(l.issue(&a,91,4,6,"198.51.100.2:443"),Decision::Denied);
    }
    #[test]fn sibling_endpoint_collision_does_not_poison() {
        let mut l=ledger();let a=owner(1,SEL);l.born(a.clone());l.born(owner(2,BRK));
        assert_eq!(flow(&mut l,&a,91),Decision::Accepted);
        let sibling=owner(7,"other");
        assert_eq!(l.issue(&sibling,91,4,6,"198.51.100.2:443"),Decision::Denied);
        assert!(!l.stopped);
        assert_eq!(l.claim(&a,91),Decision::Accepted);
    }
    #[test]fn original_app_and_reauthorization_cannot_attest() {
        let mut l=ledger();let a=owner(1,SEL);l.born(a.clone());l.born(owner(2,BRK));
        assert_eq!(l.issue(&a,91,6,6,"[2001:db8::1]:443"),Decision::Accepted);
        assert_eq!(l.attest(&a,91,6,"[2001:db8::1]:443",BRK,true,false),Decision::Denied);
        assert_eq!(l.attest(&a,91,6,"[2001:db8::1]:443",SEL,true,true),Decision::Denied);
        assert_eq!(l.attest(&a,91,6,"[2001:db8::1]:443",SEL,true,false),Decision::Accepted);
        assert_eq!(l.claim(&a,91),Decision::Accepted);
    }
    #[test]fn sibling_direct_dns_udp_and_unknown_birth_never_claim() {
        let mut l=ledger();let sibling=owner(22,"other");
        assert_eq!(l.born(sibling.clone()),Decision::Ignored);
        assert_eq!(l.issue(&sibling,7,4,6,"198.51.100.2:443"),Decision::Denied);
        let a=owner(1,SEL);l.born(a.clone());
        assert_eq!(l.issue(&a,8,4,17,"198.51.100.53:53"),Decision::Denied);
        assert_eq!(l.claim(&a,8),Decision::Denied);
    }
    #[test]fn broker_exit_or_ssh_wfp_loss_stops() {
        let mut l=ledger();let broker=owner(2,BRK);l.born(broker.clone());l.born(owner(1,SEL));
        assert_eq!(l.died(broker.pid,broker.process_ref),Decision::Stopped);
        assert_eq!(l.born(owner(3,SEL)),Decision::Stopped);
        let mut l=ledger();let a=owner(1,SEL);l.born(a.clone());l.born(owner(2,BRK));
        l.health_lost();assert_eq!(l.issue(&a,5,4,6,"1.1.1.1:443"),Decision::Stopped);
    }
    #[test]fn bounded_histories_fail_closed_not_evict() {
        let mut l=SelectiveLedger::new(Pins::new(SEL,BRK).unwrap(),1,1,1);
        let a=owner(1,SEL);l.born(a.clone());l.died(1,a.process_ref);
        assert_eq!(l.born(owner(2,SEL)),Decision::Stopped);
    }
    #[test]fn preexisting_process_never_synthesized_from_pid_lookup() {
        // A selected process that ran before the observer was initialized has
        // no birth receipt. Merely naming its PID/path cannot authorize it.
        let mut l=ledger();let preexisting=owner(5,SEL);
        assert_eq!(l.issue(&preexisting,99,4,6,"198.51.100.2:443"),Decision::Denied);
        assert_eq!(l.claim(&preexisting,99),Decision::Denied);
        assert_eq!(l.live_count(),0);
    }
    #[test]fn pin_configuration_requires_two_distinct_nonempty_paths() {
        assert!(Pins::new("",BRK).is_none());
        assert!(Pins::new(SEL,"").is_none());
        assert!(Pins::new(SEL,SEL).is_none());
    }
    #[test]fn malformed_qualified_origin_stops() {
        let mut l=ledger();let mut a=owner(1,SEL);a.file_ref=0;
        assert_eq!(l.born(a),Decision::Stopped);
    }
}
