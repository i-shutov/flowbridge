//! Offline bounded TCP lease ledger for a future independent Rust NDISRD worker.
//! Not a packet interceptor, OS owner attestation or proof of DNS leak protection.
//! Protected callers must DROP on every error, never fall back to DIRECT.

use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseError {
    InvalidConfiguration,
    InvalidTuple,
    InvalidOwner,
    NotInitialSyn,
    Capacity,
    TupleOccupied,
    Missing,
    StaleLease,
    OwnerChanged,
    Expired,
    NotActive,
    AlreadyActive,
    UpstreamUnavailable,
    ClockRewind,
    SequenceExhausted,
    Halted,
}

/// Directed outbound tuple: reversed traffic cannot be admitted as a new owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    local: SocketAddr,
    remote: SocketAddr,
}

impl FlowTuple {
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Result<Self, LeaseError> {
        if local.port() == 0
            || remote.port() == 0
            || local == remote
            || local.is_ipv4() != remote.is_ipv4()
        {
            return Err(LeaseError::InvalidTuple);
        }
        Ok(Self { local, remote })
    }

    pub fn local(self) -> SocketAddr {
        self.local
    }

    pub fn remote(self) -> SocketAddr {
        self.remote
    }
}

/// A label, not evidence of trust by itself: only the native resolver may
/// supply a PID and process creation timestamp after OS identity verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerStamp {
    pid: u32,
    created_100ns: u64,
}

impl OwnerStamp {
    pub fn new(pid: u32, created_100ns: u64) -> Result<Self, LeaseError> {
        if pid == 0 || created_100ns == 0 {
            return Err(LeaseError::InvalidOwner);
        }
        Ok(Self { pid, created_100ns })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialTcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl InitialTcpFlags {
    fn valid(self) -> bool {
        self.syn && !self.ack && !self.fin && !self.rst
    }
}

/// Staleness token, NOT a cryptographic capability. Each service process
/// must pass a new nonzero session ID from its trusted startup lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowLease {
    tuple: FlowTuple,
    session_id: u128,
    sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeasePhase {
    Pending,
    Active,
    HalfClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinSide {
    Local,
    Remote,
}

struct Entry {
    token: FlowLease,
    owner: OwnerStamp,
    last_ms: u64,
    phase: LeasePhase,
    local_fin: bool,
    remote_fin: bool,
}

/// Single-threaded state, requiring external locking and packet ordering.
pub struct TcpLeaseLedger {
    entries: HashMap<FlowTuple, Entry>,
    capacity: usize,
    idle_ms: u64,
    session_id: u128,
    sequence: u64,
    clock_ms: Option<u64>,
    halted: bool,
}

impl TcpLeaseLedger {
    pub fn new(capacity: usize, idle_ms: u64, session_id: u128) -> Result<Self, LeaseError> {
        if !(1..=65_536).contains(&capacity)
            || !(1..=86_400_000).contains(&idle_ms)
            || session_id == 0
        {
            return Err(LeaseError::InvalidConfiguration);
        }
        Ok(Self {
            entries: HashMap::new(),
            capacity,
            idle_ms,
            session_id,
            sequence: 0,
            clock_ms: None,
            halted: false,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn tick(&mut self, now_ms: u64) -> Result<(), LeaseError> {
        if self.halted {
            return Err(LeaseError::Halted);
        }
        if self.clock_ms.is_some_and(|prior| now_ms < prior) {
            self.shutdown();
            return Err(LeaseError::ClockRewind);
        }
        self.clock_ms = Some(now_ms);
        Ok(())
    }

    fn reap(&mut self, now_ms: u64) -> usize {
        let old = self.entries.len();
        self.entries
            .retain(|_, entry| now_ms - entry.last_ms < self.idle_ms);
        old - self.entries.len()
    }

    pub fn expire(&mut self, now_ms: u64) -> Result<usize, LeaseError> {
        self.tick(now_ms)?;
        Ok(self.reap(now_ms))
    }

    /// Admit ONLY an initial outbound SYN after independent capture policy
    /// and IP Helper checks. Pending is never routable.
    pub fn begin_syn(
        &mut self,
        tuple: FlowTuple,
        owner: OwnerStamp,
        flags: InitialTcpFlags,
        now_ms: u64,
    ) -> Result<FlowLease, LeaseError> {
        self.tick(now_ms)?;
        if !flags.valid() {
            return Err(LeaseError::NotInitialSyn);
        }
        self.reap(now_ms);
        if self.entries.contains_key(&tuple) {
            return Err(LeaseError::TupleOccupied);
        }
        if self.entries.len() >= self.capacity {
            return Err(LeaseError::Capacity);
        }
        let sequence = match self.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                self.shutdown();
                return Err(LeaseError::SequenceExhausted);
            }
        };
        self.sequence = sequence;
        let token = FlowLease {
            tuple,
            session_id: self.session_id,
            sequence,
        };
        self.entries.insert(
            tuple,
            Entry {
                token,
                owner,
                last_ms: now_ms,
                phase: LeasePhase::Pending,
                local_fin: false,
                remote_fin: false,
            },
        );
        Ok(token)
    }

    fn check(
        &mut self,
        token: FlowLease,
        owner: OwnerStamp,
        now_ms: u64,
    ) -> Result<(), LeaseError> {
        self.tick(now_ms)?;
        if token.session_id != self.session_id {
            return Err(LeaseError::StaleLease);
        }
        let entry = self.entries.get(&token.tuple).ok_or(LeaseError::Missing)?;
        if entry.token != token {
            return Err(LeaseError::StaleLease);
        }
        if entry.owner != owner {
            self.entries.remove(&token.tuple);
            return Err(LeaseError::OwnerChanged);
        }
        if now_ms - entry.last_ms >= self.idle_ms {
            self.entries.remove(&token.tuple);
            return Err(LeaseError::Expired);
        }
        Ok(())
    }

    /// Retransmission does not extend the pending timeout or replace identity.
    pub fn verify_retransmit(
        &mut self,
        token: FlowLease,
        owner: OwnerStamp,
        flags: InitialTcpFlags,
        now_ms: u64,
    ) -> Result<(), LeaseError> {
        self.check(token, owner, now_ms)?;
        if !flags.valid() {
            return Err(LeaseError::NotInitialSyn);
        }
        if self.entries[&token.tuple].phase != LeasePhase::Pending {
            return Err(LeaseError::AlreadyActive);
        }
        Ok(())
    }

    /// Only the supervised SOCKS-to-SSH worker may assert upstream readiness;
    /// false discards the pending lease, with no DIRECT fallback.
    pub fn activate(
        &mut self,
        token: FlowLease,
        owner: OwnerStamp,
        now_ms: u64,
        upstream_connected: bool,
    ) -> Result<(), LeaseError> {
        self.check(token, owner, now_ms)?;
        if !upstream_connected {
            self.entries.remove(&token.tuple);
            return Err(LeaseError::UpstreamUnavailable);
        }
        let entry = self
            .entries
            .get_mut(&token.tuple)
            .ok_or(LeaseError::Missing)?;
        if entry.phase != LeasePhase::Pending {
            return Err(LeaseError::AlreadyActive);
        }
        entry.phase = LeasePhase::Active;
        entry.last_ms = now_ms;
        Ok(())
    }

    /// The caller MUST additionally recheck OS ownership and capture policy;
    /// a valid state token alone never authorizes injection or filtering.
    pub fn check_active(
        &mut self,
        token: FlowLease,
        owner: OwnerStamp,
        now_ms: u64,
    ) -> Result<LeasePhase, LeaseError> {
        self.check(token, owner, now_ms)?;
        let entry = self
            .entries
            .get_mut(&token.tuple)
            .ok_or(LeaseError::Missing)?;
        if entry.phase == LeasePhase::Pending {
            return Err(LeaseError::NotActive);
        }
        entry.last_ms = now_ms;
        Ok(entry.phase)
    }

    /// FIN tracking is only lifecycle bookkeeping, NOT TCP sequence/ACK logic.
    /// Keep the lease after both FINs: final ACKs may still be in flight.
    /// Only explicit terminal confirmation, RST, or expiry may retire it.
    pub fn note_fin(
        &mut self,
        token: FlowLease,
        owner: OwnerStamp,
        now_ms: u64,
        side: FinSide,
    ) -> Result<bool, LeaseError> {
        self.check(token, owner, now_ms)?;
        let entry = self
            .entries
            .get_mut(&token.tuple)
            .ok_or(LeaseError::Missing)?;
        if entry.phase == LeasePhase::Pending {
            return Err(LeaseError::NotActive);
        }
        match side {
            FinSide::Local => entry.local_fin = true,
            FinSide::Remote => entry.remote_fin = true,
        }
        entry.phase = LeasePhase::HalfClosed;
        entry.last_ms = now_ms;
        let both_fin = entry.local_fin && entry.remote_fin;
        // Seeing both FINs is not proof that the final ACKs have arrived.
        Ok(both_fin)
    }

    pub fn retire(
        &mut self,
        token: FlowLease,
        owner: OwnerStamp,
        now_ms: u64,
    ) -> Result<(), LeaseError> {
        self.check(token, owner, now_ms)?;
        self.entries.remove(&token.tuple);
        Ok(())
    }

    /// Remove ONLY an exact owned ticket after an async stream terminates.
    /// This is a destructive cleanup operation, NEVER an authorization check:
    /// it deliberately does not tick the shared packet-worker clock. Using a
    /// delayed async completion timestamp to call retire() could falsely
    /// trigger ClockRewind and shut down unrelated healthy flows.
    pub fn finish_stream(&mut self, token: FlowLease, owner: OwnerStamp) -> Result<(), LeaseError> {
        if self.halted {
            return Err(LeaseError::Halted);
        }
        if token.session_id != self.session_id {
            return Err(LeaseError::StaleLease);
        }
        let entry = self.entries.get(&token.tuple).ok_or(LeaseError::Missing)?;
        if entry.token != token {
            return Err(LeaseError::StaleLease);
        }
        if entry.owner != owner {
            self.entries.remove(&token.tuple);
            return Err(LeaseError::OwnerChanged);
        }
        self.entries.remove(&token.tuple);
        Ok(())
    }

    /// Revokes everything on SSH loss, worker shutdown or uncertain cleanup.
    /// A fresh ledger MUST use a different trusted session ID.
    pub fn shutdown(&mut self) {
        self.entries.clear();
        self.halted = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4() -> FlowTuple {
        FlowTuple::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44001),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), 443),
        )
        .unwrap()
    }
    fn v6() -> FlowTuple {
        FlowTuple::new(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 44001),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
        )
        .unwrap()
    }
    fn owner() -> OwnerStamp {
        OwnerStamp::new(811, 123456789).unwrap()
    }
    fn syn() -> InitialTcpFlags {
        InitialTcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
        }
    }
    fn ledger() -> TcpLeaseLedger {
        TcpLeaseLedger::new(2, 100, 101).unwrap()
    }

    #[test]
    fn stream_completion_is_clock_independent_but_generation_and_owner_bound() {
        let mut ledger = ledger();
        let first = ledger.begin_syn(v4(), owner(), syn(), 100).unwrap();
        ledger.activate(first, owner(), 101, true).unwrap();
        // An async completion is allowed after the packet-worker clock advances,
        // with no stale timestamp assertion or accidental clock rewind.
        ledger.expire(110).unwrap();
        ledger.finish_stream(first, owner()).unwrap();
        assert!(ledger.is_empty());
        assert_eq!(
            ledger.finish_stream(first, owner()),
            Err(LeaseError::Missing)
        );

        let new = ledger.begin_syn(v4(), owner(), syn(), 120).unwrap();
        assert_ne!(first, new);
        assert_eq!(
            ledger.finish_stream(first, owner()),
            Err(LeaseError::StaleLease)
        );
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.finish_stream(new, OwnerStamp::new(811, 999).unwrap()),
            Err(LeaseError::OwnerChanged)
        );
        assert!(ledger.is_empty());
        let another = ledger.begin_syn(v4(), owner(), syn(), 130).unwrap();
        ledger.shutdown();
        assert_eq!(
            ledger.finish_stream(another, owner()),
            Err(LeaseError::Halted)
        );
    }

    #[test]
    fn strict_configuration_tuple_and_owner_validation() {
        assert!(TcpLeaseLedger::new(0, 100, 1).is_err());
        assert!(TcpLeaseLedger::new(1, 0, 1).is_err());
        assert!(TcpLeaseLedger::new(1, 100, 0).is_err());
        assert_eq!(OwnerStamp::new(0, 1), Err(LeaseError::InvalidOwner));
        assert_eq!(OwnerStamp::new(1, 0), Err(LeaseError::InvalidOwner));
        let a = v4();
        assert_eq!(a.local().port(), 44001);
        assert_eq!(a.remote().port(), 443);
        assert_eq!(
            FlowTuple::new(a.local(), a.local()),
            Err(LeaseError::InvalidTuple)
        );
        assert_eq!(
            FlowTuple::new(a.local(), v6().remote()),
            Err(LeaseError::InvalidTuple)
        );
        assert_eq!(
            FlowTuple::new(SocketAddr::new(a.local().ip(), 0), a.remote()),
            Err(LeaseError::InvalidTuple)
        );
    }

    #[test]
    fn only_initial_syn_and_pending_never_routable() {
        let mut l = ledger();
        for flags in [
            InitialTcpFlags {
                syn: false,
                ..syn()
            },
            InitialTcpFlags { ack: true, ..syn() },
            InitialTcpFlags { fin: true, ..syn() },
            InitialTcpFlags { rst: true, ..syn() },
        ] {
            assert_eq!(
                l.begin_syn(v4(), owner(), flags, 1),
                Err(LeaseError::NotInitialSyn)
            );
        }
        let t = l.begin_syn(v4(), owner(), syn(), 2).unwrap();
        assert_eq!(l.check_active(t, owner(), 3), Err(LeaseError::NotActive));
        assert_eq!(l.verify_retransmit(t, owner(), syn(), 4), Ok(()));
    }

    #[test]
    fn unavailable_upstream_revokes_and_does_not_fallback() {
        let mut l = ledger();
        let t = l.begin_syn(v4(), owner(), syn(), 1).unwrap();
        assert_eq!(
            l.activate(t, owner(), 2, false),
            Err(LeaseError::UpstreamUnavailable)
        );
        assert_eq!(l.check_active(t, owner(), 3), Err(LeaseError::Missing));
        let fresh = l.begin_syn(v4(), owner(), syn(), 4).unwrap();
        assert_ne!(t, fresh);
        l.activate(fresh, owner(), 5, true).unwrap();
        assert_eq!(l.check_active(fresh, owner(), 6), Ok(LeasePhase::Active));
        assert_eq!(
            l.activate(fresh, owner(), 7, true),
            Err(LeaseError::AlreadyActive)
        );
    }

    #[test]
    fn pid_creation_time_change_revokes_the_flow() {
        let mut l = ledger();
        let t = l.begin_syn(v4(), owner(), syn(), 1).unwrap();
        l.activate(t, owner(), 2, true).unwrap();
        let changed = OwnerStamp::new(811, 123456790).unwrap();
        assert_eq!(l.check_active(t, changed, 3), Err(LeaseError::OwnerChanged));
        assert_eq!(l.check_active(t, owner(), 4), Err(LeaseError::Missing));
        assert!(l.is_empty());
    }

    #[test]
    fn collisions_and_capacity_do_not_replace_live_flows() {
        let mut l = TcpLeaseLedger::new(1, 100, 27).unwrap();
        let t = l.begin_syn(v4(), owner(), syn(), 1).unwrap();
        assert_eq!(
            l.begin_syn(v4(), owner(), syn(), 2),
            Err(LeaseError::TupleOccupied)
        );
        assert_eq!(
            l.begin_syn(v6(), owner(), syn(), 3),
            Err(LeaseError::Capacity)
        );
        l.activate(t, owner(), 4, true).unwrap();
        assert_eq!(l.check_active(t, owner(), 5), Ok(LeasePhase::Active));
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn sequence_session_and_reverse_tuple_are_distinct() {
        let mut l = ledger();
        let old = l.begin_syn(v4(), owner(), syn(), 1).unwrap();
        l.retire(old, owner(), 2).unwrap();
        let current = l.begin_syn(v4(), owner(), syn(), 3).unwrap();
        assert_eq!(
            l.activate(old, owner(), 4, true),
            Err(LeaseError::StaleLease)
        );
        l.activate(current, owner(), 5, true).unwrap();
        let mut restarted = TcpLeaseLedger::new(2, 100, 202).unwrap();
        let _ = restarted.begin_syn(v4(), owner(), syn(), 5).unwrap();
        assert_eq!(
            restarted.check_active(current, owner(), 6),
            Err(LeaseError::StaleLease)
        );
        let reversed = FlowTuple::new(v4().remote(), v4().local()).unwrap();
        l.begin_syn(reversed, owner(), syn(), 7).unwrap();
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn pending_retransmit_does_not_extend_idle_expiry() {
        let mut l = ledger();
        let old = l.begin_syn(v4(), owner(), syn(), 10).unwrap();
        l.verify_retransmit(old, owner(), syn(), 80).unwrap();
        assert_eq!(
            l.verify_retransmit(old, owner(), syn(), 110),
            Err(LeaseError::Expired)
        );
        let fresh = l.begin_syn(v4(), owner(), syn(), 111).unwrap();
        assert_ne!(old, fresh);
        assert_eq!(l.expire(211), Ok(1));
    }

    #[test]
    fn active_traffic_extends_idle_expiry() {
        let mut l = ledger();
        let t = l.begin_syn(v4(), owner(), syn(), 5).unwrap();
        l.activate(t, owner(), 6, true).unwrap();
        assert_eq!(l.check_active(t, owner(), 80), Ok(LeasePhase::Active));
        assert_eq!(l.expire(170), Ok(0));
        assert_eq!(l.expire(180), Ok(1));
        assert_eq!(l.check_active(t, owner(), 181), Err(LeaseError::Missing));
    }

    #[test]
    fn both_fin_keep_lease_until_explicit_terminal_confirmation() {
        let mut l = ledger();
        let t = l.begin_syn(v6(), owner(), syn(), 1).unwrap();
        l.activate(t, owner(), 2, true).unwrap();
        assert_eq!(l.note_fin(t, owner(), 3, FinSide::Local), Ok(false));
        assert_eq!(l.note_fin(t, owner(), 4, FinSide::Local), Ok(false));
        assert_eq!(l.check_active(t, owner(), 5), Ok(LeasePhase::HalfClosed));
        assert_eq!(l.note_fin(t, owner(), 6, FinSide::Remote), Ok(true));
        assert_eq!(l.check_active(t, owner(), 7), Ok(LeasePhase::HalfClosed));
        l.retire(t, owner(), 8).unwrap(); // explicit terminal confirmation
        assert_eq!(l.check_active(t, owner(), 9), Err(LeaseError::Missing));
    }

    #[test]
    fn clock_rewind_halts_and_revokes_everything() {
        let mut l = ledger();
        let t = l.begin_syn(v4(), owner(), syn(), 100).unwrap();
        assert_eq!(l.check_active(t, owner(), 99), Err(LeaseError::ClockRewind));
        assert!(l.is_empty());
        assert_eq!(
            l.begin_syn(v4(), owner(), syn(), 101),
            Err(LeaseError::Halted)
        );
    }

    #[test]
    fn shutdown_and_sequence_overflow_are_terminal() {
        let mut l = ledger();
        let t = l.begin_syn(v4(), owner(), syn(), 1).unwrap();
        l.shutdown();
        assert_eq!(l.activate(t, owner(), 2, true), Err(LeaseError::Halted));
        assert_eq!(
            l.begin_syn(v6(), owner(), syn(), 3),
            Err(LeaseError::Halted)
        );
        let mut exhausted = ledger();
        exhausted.sequence = u64::MAX;
        assert_eq!(
            exhausted.begin_syn(v4(), owner(), syn(), 1),
            Err(LeaseError::SequenceExhausted)
        );
        assert_eq!(
            exhausted.begin_syn(v4(), owner(), syn(), 2),
            Err(LeaseError::Halted)
        );
    }
}
