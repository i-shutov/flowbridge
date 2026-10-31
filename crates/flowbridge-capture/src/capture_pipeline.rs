//! Composed policy -> lease -> bidirectional Ethernet/TCP transformation.
//! This is the in-process integration boundary, not native owner attestation.
//! IP Helper snapshots alone are explicitly rejected. No JSON/FFI input may
//! promote them to PacketBound. The current native agent DOES NOT do so.

use flowbridge_core::capture_policy::{
    CapturePolicy, Process, ProtectedReadiness, Protocol, Route,
};
use flowbridge_core::ndis_frame_tcp::{
    inspect_ethernet_tcp, rewrite_ethernet_tcp_tuple, FrameTcpError,
};
use flowbridge_core::tcp_flow_lease::{
    FinSide, FlowLease, FlowTuple, InitialTcpFlags, LeaseError, OwnerStamp, TcpLeaseLedger,
};
use flowbridge_core::tcp_packet::TcpTuple;
use flowbridge_core::{Action, Config, Endpoint, Flow};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineError {
    Frame(FrameTcpError),
    Lease(LeaseError),
    SnapshotNotAuthority,
    AdapterMismatch,
    PolicyBlocked,
    NotProxyRoute,
    InvalidAlias,
    TupleMismatch,
    AliasOccupied,
    UnknownTicket,
    OwnerChanged,
    Halted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    SnapshotCandidate,
    PacketBound,
}

/// Produced only by a trusted native boundary; not deserializable. PacketBound
/// remains unavailable in the shipped agent pending actual Win10/11 evidence.
#[derive(Clone, Copy)]
pub struct OwnerEvidence<'a> {
    pub stamp: OwnerStamp,
    pub path: &'a str,
    pub kind: EvidenceKind,
}

#[derive(Clone, Copy)]
pub struct PacketContext<'a> {
    pub adapter: u64,
    pub owner: OwnerEvidence<'a>,
    pub readiness: ProtectedReadiness,
    pub now_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    ApplicationToRelay,
    RelayToApplication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    tuple: FlowTuple,
    lease: FlowLease,
}

struct BoundFlow {
    lease: FlowLease,
    owner: OwnerStamp,
    path: String,
    original: TcpTuple,
    alias: TcpTuple,
    last_ms: u64,
}

pub struct CapturePipeline {
    adapter: u64,
    policy: CapturePolicy,
    config: Config,
    ledger: TcpLeaseLedger,
    flows: HashMap<FlowTuple, BoundFlow>,
    aliases: HashMap<FlowTuple, FlowTuple>,
    scratch: Vec<u8>,
    halted: bool,
    idle_ms: u64,
}

fn reverse(t: TcpTuple) -> TcpTuple {
    TcpTuple {
        source: t.destination,
        destination: t.source,
    }
}
fn flow_tuple(t: TcpTuple) -> Result<FlowTuple, PipelineError> {
    FlowTuple::new(t.source, t.destination).map_err(PipelineError::Lease)
}

impl CapturePipeline {
    pub fn new(
        adapter: u64,
        session: u128,
        selected: &[String],
        config: Config,
    ) -> Result<Self, PipelineError> {
        if adapter == 0 || config.validate().is_err() {
            return Err(PipelineError::PolicyBlocked);
        }
        let ledger = TcpLeaseLedger::new(config.max_connections, config.idle_timeout_ms, session)
            .map_err(PipelineError::Lease)?;
        let policy =
            CapturePolicy::new(selected, true, true).map_err(|_| PipelineError::PolicyBlocked)?;
        let idle_ms = config.idle_timeout_ms;
        Ok(Self {
            adapter,
            policy,
            config,
            ledger,
            flows: HashMap::new(),
            aliases: HashMap::new(),
            scratch: vec![0; 9216],
            halted: false,
            idle_ms,
        })
    }

    fn guard(&mut self, adapter: u64, readiness: ProtectedReadiness) -> Result<(), PipelineError> {
        if self.halted {
            return Err(PipelineError::Halted);
        }
        if adapter != self.adapter {
            return Err(PipelineError::AdapterMismatch);
        }
        if !readiness.complete() {
            self.revoke_all();
            return Err(PipelineError::PolicyBlocked);
        }
        Ok(())
    }

    /// Keep the alias index and the core lease ledger at the same generation.
    /// Packet-controlled errors never extend an entry's timeout.
    fn reap(&mut self, now_ms: u64) -> Result<(), PipelineError> {
        if let Err(error) = self.ledger.expire(now_ms) {
            self.revoke_all();
            return Err(PipelineError::Lease(error));
        }
        self.flows
            .retain(|_, entry| now_ms.saturating_sub(entry.last_ms) < self.idle_ms);
        self.aliases
            .retain(|_, tuple| self.flows.contains_key(tuple));
        Ok(())
    }

    /// Reserve state only for a selected, packet-bound initial SYN. The alias
    /// models a local relay on this adapter, never an arbitrary remote route.
    /// No packets are changed, accepted, or sent by this reservation.
    pub fn begin(
        &mut self,
        context: PacketContext<'_>,
        frame: &[u8],
        alias: TcpTuple,
    ) -> Result<Ticket, PipelineError> {
        let PacketContext {
            adapter,
            owner,
            readiness,
            now_ms,
        } = context;
        self.guard(adapter, readiness)?;
        self.reap(now_ms)?;
        if owner.kind != EvidenceKind::PacketBound {
            return Err(PipelineError::SnapshotNotAuthority);
        }
        if self
            .policy
            .route_protected(Process::Attested(owner.path), Protocol::Tcp, readiness)
            .route
            != Route::Proxy
        {
            return Err(PipelineError::PolicyBlocked);
        }
        let parsed = inspect_ethernet_tcp(frame).map_err(PipelineError::Frame)?;
        let original = parsed.tcp.tuple;
        let tuple = flow_tuple(original)?;
        let alias_key = flow_tuple(reverse(alias))?;
        if alias.source.ip() != original.destination.ip()
            || alias.destination.ip() != original.source.ip()
            || alias == reverse(original)
            || alias.destination.port() == original.source.port()
        {
            return Err(PipelineError::InvalidAlias);
        }
        if self.aliases.contains_key(&alias_key) {
            return Err(PipelineError::AliasOccupied);
        }
        let decision = self.config.evaluate(&Flow {
            application: Some(owner.path.to_owned()),
            destination: Endpoint {
                host: original.destination.ip().to_string(),
                port: original.destination.port(),
            },
            resolved_ip: Some(original.destination.ip()),
        });
        if !matches!(decision.action, Action::Proxy { .. } | Action::Chain { .. }) {
            // Explicit DIRECT exceptions are handled outside a redirected lease.
            // A proxy failure must NEVER enter that separate path.
            return Err(PipelineError::NotProxyRoute);
        }
        let ip = &frame[parsed.region.offset..parsed.region.offset + parsed.region.length];
        let tcp_start = if ip[0] >> 4 == 4 {
            usize::from(ip[0] & 15) * 4
        } else {
            40
        };
        let flags = ip[tcp_start + 13];
        let lease = self
            .ledger
            .begin_syn(
                tuple,
                owner.stamp,
                InitialTcpFlags {
                    syn: flags & 2 != 0,
                    ack: flags & 16 != 0,
                    fin: flags & 1 != 0,
                    rst: flags & 4 != 0,
                },
                now_ms,
            )
            .map_err(PipelineError::Lease)?;
        self.flows.insert(
            tuple,
            BoundFlow {
                lease,
                owner: owner.stamp,
                path: owner.path.to_owned(),
                original,
                alias,
                last_ms: now_ms,
            },
        );
        self.aliases.insert(alias_key, tuple);
        Ok(Ticket { tuple, lease })
    }

    pub fn destination(
        &mut self,
        ticket: Ticket,
        context: PacketContext<'_>,
    ) -> Result<Endpoint, PipelineError> {
        self.guard(context.adapter, context.readiness)?;
        self.reap(context.now_ms)?;
        let flow = self.bound(ticket, &context.owner)?;
        Ok(Endpoint {
            host: flow.original.destination.ip().to_string(),
            port: flow.original.destination.port(),
        })
    }

    fn bound(
        &self,
        ticket: Ticket,
        owner: &OwnerEvidence<'_>,
    ) -> Result<&BoundFlow, PipelineError> {
        if owner.kind != EvidenceKind::PacketBound {
            return Err(PipelineError::SnapshotNotAuthority);
        }
        let flow = self
            .flows
            .get(&ticket.tuple)
            .ok_or(PipelineError::UnknownTicket)?;
        if flow.lease != ticket.lease {
            return Err(PipelineError::UnknownTicket);
        }
        if flow.owner != owner.stamp || flow.path != owner.path {
            return Err(PipelineError::OwnerChanged);
        }
        Ok(flow)
    }

    /// Call only AFTER the real SOCKS CONNECT has succeeded, never after a mere
    /// TCP listener probe. Failure retires state and cannot select DIRECT.
    pub fn activate(
        &mut self,
        ticket: Ticket,
        owner: OwnerEvidence<'_>,
        now_ms: u64,
        connected: bool,
    ) -> Result<(), PipelineError> {
        self.reap(now_ms)?;
        if let Err(error) = self.bound(ticket, &owner) {
            self.revoke_all();
            return Err(error);
        }
        match self
            .ledger
            .activate(ticket.lease, owner.stamp, now_ms, connected)
        {
            Ok(()) => {
                if let Some(flow) = self.flows.get_mut(&ticket.tuple) {
                    flow.last_ms = now_ms;
                }
                Ok(())
            }
            Err(error) => {
                let _ = self.ledger.retire(ticket.lease, owner.stamp, now_ms);
                self.remove(ticket);
                Err(PipelineError::Lease(error))
            }
        }
    }

    fn remove(&mut self, ticket: Ticket) {
        if self
            .flows
            .get(&ticket.tuple)
            .is_some_and(|f| f.lease == ticket.lease)
        {
            if let Some(flow) = self.flows.remove(&ticket.tuple) {
                if let Ok(alias) = flow_tuple(reverse(flow.alias)) {
                    self.aliases.remove(&alias);
                }
            }
        }
    }

    pub fn rewrite(
        &mut self,
        ticket: Ticket,
        context: PacketContext<'_>,
        leg: Leg,
        frame: &mut [u8],
    ) -> Result<(), PipelineError> {
        let PacketContext {
            adapter,
            owner,
            readiness,
            now_ms,
        } = context;
        self.guard(adapter, readiness)?;
        self.reap(now_ms)?;
        let (original, alias) = {
            let bound = match self.bound(ticket, &owner) {
                Ok(bound) => bound,
                Err(error) => {
                    self.revoke_all();
                    return Err(error);
                }
            };
            (bound.original, bound.alias)
        };
        let (expected, replacement) = match leg {
            Leg::ApplicationToRelay => (original, alias),
            Leg::RelayToApplication => (reverse(alias), reverse(original)),
        };
        // Validate the complete frame and direction before touching its lease.
        let inspected = inspect_ethernet_tcp(frame).map_err(PipelineError::Frame)?;
        if inspected.tcp.tuple != expected {
            return Err(PipelineError::TupleMismatch);
        }
        if let Err(error) = self.ledger.check_active(ticket.lease, owner.stamp, now_ms) {
            let _ = self.ledger.retire(ticket.lease, owner.stamp, now_ms);
            self.remove(ticket);
            return Err(PipelineError::Lease(error));
        }
        // All validation/mutation is transactional inside the existing primitive.
        let info = rewrite_ethernet_tcp_tuple(frame, &mut self.scratch, expected, replacement)
            .map_err(PipelineError::Frame)?;
        if let Some(flow) = self.flows.get_mut(&ticket.tuple) {
            flow.last_ms = now_ms;
        }
        // The reflected packet is injected toward the local TCP/IP stack;
        // swap Ethernet source/destination while preserving VLAN and payload.
        for i in 0..6 {
            frame.swap(i, i + 6);
        }
        let ip = &frame[info.region.offset..info.region.offset + info.region.length];
        let tcp_start = if ip[0] >> 4 == 4 {
            usize::from(ip[0] & 15) * 4
        } else {
            40
        };
        let flags = ip[tcp_start + 13];
        if flags & 4 != 0 {
            // Validation of TCP sequence/ACK belongs to the native stack.
            let _ = self.ledger.retire(ticket.lease, owner.stamp, now_ms);
            self.remove(ticket);
        } else if flags & 1 != 0 {
            let side = if leg == Leg::ApplicationToRelay {
                FinSide::Local
            } else {
                FinSide::Remote
            };
            let _ = self
                .ledger
                .note_fin(ticket.lease, owner.stamp, now_ms, side);
        }
        Ok(())
    }

    pub fn retire(
        &mut self,
        ticket: Ticket,
        owner: OwnerEvidence<'_>,
        now_ms: u64,
    ) -> Result<(), PipelineError> {
        self.reap(now_ms)?;
        self.bound(ticket, &owner)?;
        let result = self
            .ledger
            .retire(ticket.lease, owner.stamp, now_ms)
            .map_err(PipelineError::Lease);
        self.remove(ticket);
        result
    }

    pub fn revoke_all(&mut self) {
        self.halted = true;
        self.ledger.shutdown();
        self.flows.clear();
        self.aliases.clear();
    }
    pub fn active_records(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use flowbridge_core::{Proxy, ProxyKind};
    use std::net::IpAddr;

    const PATH: &str = r"C:\Apps\Browser.exe";
    pub(crate) fn context(now_ms: u64) -> PacketContext<'static> {
        PacketContext {
            adapter: 7,
            owner: OwnerEvidence {
                stamp: OwnerStamp::new(47, 900).unwrap(),
                path: PATH,
                kind: EvidenceKind::PacketBound,
            },
            readiness: ProtectedReadiness {
                driver_tunnel_confirmed: true,
                owner_revalidated: true,
                ssh_upstream_healthy: true,
                dns_udp_contained: true,
                rollback_guard_armed: true,
            },
            now_ms,
        }
    }
    pub(crate) fn setup() -> CapturePipeline {
        setup_with_idle(100)
    }
    pub(crate) fn setup_with_idle(idle_ms: u64) -> CapturePipeline {
        let mut config: Config =
            serde_json::from_str(include_str!("../../../examples/direct.json")).unwrap();
        config.proxies.push(Proxy {
            id: "ssh".into(),
            kind: ProxyKind::Socks5,
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port: 1080,
            },
            username: None,
            password_env: None,
        });
        config.default_action = Action::Proxy { id: "ssh".into() };
        config.max_connections = 2;
        config.idle_timeout_ms = idle_ms;
        CapturePipeline::new(7, 17, &[PATH.into()], config).unwrap()
    }
    pub(crate) fn tuple(ipv6: bool) -> TcpTuple {
        if ipv6 {
            TcpTuple {
                source: "[2001:db8::1]:40001".parse().unwrap(),
                destination: "[2001:db8::2]:443".parse().unwrap(),
            }
        } else {
            TcpTuple {
                source: "192.0.2.1:40001".parse().unwrap(),
                destination: "198.51.100.2:443".parse().unwrap(),
            }
        }
    }
    pub(crate) fn alias(original: TcpTuple) -> TcpTuple {
        TcpTuple {
            source: std::net::SocketAddr::new(original.destination.ip(), 52000),
            destination: std::net::SocketAddr::new(original.source.ip(), 18080),
        }
    }
    fn sum(data: &[u8]) -> u16 {
        let mut acc = 0u32;
        for pair in data.chunks(2) {
            acc += (u32::from(pair[0]) << 8) + u32::from(*pair.get(1).unwrap_or(&0));
        }
        while acc >> 16 != 0 {
            acc = (acc & 65535) + (acc >> 16);
        }
        !(acc as u16)
    }
    pub(crate) fn frame(tuple: TcpTuple, flags: u8) -> Vec<u8> {
        let ipv6 = tuple.source.is_ipv6();
        let offset = if ipv6 { 40 } else { 20 };
        let mut ip = vec![0; offset + 20];
        let mut pseudo = Vec::new();
        match (tuple.source.ip(), tuple.destination.ip()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                ip[0] = 0x45;
                ip[2..4].copy_from_slice(&40u16.to_be_bytes());
                ip[8] = 64;
                ip[9] = 6;
                ip[12..16].copy_from_slice(&a.octets());
                ip[16..20].copy_from_slice(&b.octets());
                let checksum = sum(&ip[..20]);
                ip[10..12].copy_from_slice(&checksum.to_be_bytes());
                pseudo.extend(a.octets());
                pseudo.extend(b.octets());
                pseudo.extend([0, 6, 0, 20]);
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                ip[0] = 0x60;
                ip[4..6].copy_from_slice(&20u16.to_be_bytes());
                ip[6] = 6;
                ip[7] = 64;
                ip[8..24].copy_from_slice(&a.octets());
                ip[24..40].copy_from_slice(&b.octets());
                pseudo.extend(a.octets());
                pseudo.extend(b.octets());
                pseudo.extend(20u32.to_be_bytes());
                pseudo.extend([0, 0, 0, 6]);
            }
            _ => panic!("fixture family mismatch"),
        }
        ip[offset..offset + 2].copy_from_slice(&tuple.source.port().to_be_bytes());
        ip[offset + 2..offset + 4].copy_from_slice(&tuple.destination.port().to_be_bytes());
        ip[offset + 12] = 0x50;
        ip[offset + 13] = flags;
        pseudo.extend(&ip[offset..]);
        let checksum = sum(&pseudo);
        ip[offset + 16..offset + 18].copy_from_slice(&checksum.to_be_bytes());
        let mut out = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x88, 0xa8, 0, 7, 0x81, 0, 0, 9,
        ];
        out.extend(if ipv6 { [0x86, 0xdd] } else { [0x08, 0x00] });
        out.extend(ip);
        out
    }

    #[test]
    fn v4_v6_qinq_syn_to_reply_is_one_composed_stateful_path() {
        for v6 in [false, true] {
            let mut p = setup();
            let original = tuple(v6);
            let translated = alias(original);
            let syn = frame(original, 2);
            let ticket = p.begin(context(1), &syn, translated).unwrap();
            p.activate(ticket, context(2).owner, 2, true).unwrap();
            let mut outgoing = syn.clone();
            p.rewrite(ticket, context(3), Leg::ApplicationToRelay, &mut outgoing)
                .unwrap();
            assert_eq!(
                inspect_ethernet_tcp(&outgoing).unwrap().tcp.tuple,
                translated
            );
            assert_eq!(&outgoing[..6], &syn[6..12]);
            assert_eq!(&outgoing[12..22], &syn[12..22]);
            let mut reply = frame(reverse(translated), 0x12);
            p.rewrite(ticket, context(4), Leg::RelayToApplication, &mut reply)
                .unwrap();
            assert_eq!(
                inspect_ethernet_tcp(&reply).unwrap().tcp.tuple,
                reverse(original)
            );
            p.retire(ticket, context(5).owner, 5).unwrap();
            assert_eq!(p.active_records(), 0);
        }
    }

    #[test]
    fn snapshot_candidates_cannot_authorize_and_proxy_failure_never_becomes_direct() {
        let mut p = setup();
        let original = tuple(false);
        let syn = frame(original, 2);
        let mut snapshot = context(1);
        snapshot.owner.kind = EvidenceKind::SnapshotCandidate;
        assert_eq!(
            p.begin(snapshot, &syn, alias(original)),
            Err(PipelineError::SnapshotNotAuthority)
        );
        assert_eq!(p.active_records(), 0);
        let ticket = p.begin(context(2), &syn, alias(original)).unwrap();
        assert_eq!(
            p.activate(ticket, context(3).owner, 3, false),
            Err(PipelineError::Lease(LeaseError::UpstreamUnavailable))
        );
        assert_eq!(p.active_records(), 0);
        let mut data = syn.clone();
        assert!(p
            .rewrite(ticket, context(4), Leg::ApplicationToRelay, &mut data)
            .is_err());
        assert_eq!(data, syn);
    }

    #[test]
    fn pending_and_pid_reuse_are_rejected_without_frame_mutation() {
        let original = tuple(false);
        let syn = frame(original, 2);
        let mut p = setup();
        let ticket = p.begin(context(1), &syn, alias(original)).unwrap();
        let mut data = syn.clone();
        assert_eq!(
            p.rewrite(ticket, context(2), Leg::ApplicationToRelay, &mut data),
            Err(PipelineError::Lease(LeaseError::NotActive))
        );
        assert_eq!(data, syn);
        assert_eq!(p.active_records(), 0);
        let mut p = setup();
        let ticket = p.begin(context(1), &syn, alias(original)).unwrap();
        p.activate(ticket, context(2).owner, 2, true).unwrap();
        let mut reused = context(3);
        reused.owner.stamp = OwnerStamp::new(47, 901).unwrap();
        assert_eq!(
            p.rewrite(ticket, reused, Leg::ApplicationToRelay, &mut data),
            Err(PipelineError::OwnerChanged)
        );
        assert_eq!(data, syn);
        assert_eq!(p.active_records(), 0);
    }

    #[test]
    fn expiry_reclaims_alias_index_and_old_ticket_cannot_match_new_generation() {
        let original = tuple(false);
        let syn = frame(original, 2);
        let mut p = setup();
        let old = p.begin(context(1), &syn, alias(original)).unwrap();
        let new = p.begin(context(101), &syn, alias(original)).unwrap();
        assert_ne!(new, old);
        assert_eq!(p.active_records(), 1);
        assert_eq!(
            p.activate(old, context(102).owner, 102, true),
            Err(PipelineError::UnknownTicket)
        );
        assert_eq!(p.active_records(), 0);
    }

    #[test]
    fn invalid_packet_does_not_refresh_idle_timeout_and_ssh_loss_revokes_all() {
        let original = tuple(false);
        let syn = frame(original, 2);
        let mut p = setup();
        let ticket = p.begin(context(1), &syn, alias(original)).unwrap();
        p.activate(ticket, context(2).owner, 2, true).unwrap();
        let mut bad = syn.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(p
            .rewrite(ticket, context(90), Leg::ApplicationToRelay, &mut bad)
            .is_err());
        let new = p.begin(context(102), &syn, alias(original)).unwrap();
        p.activate(new, context(103).owner, 103, true).unwrap();
        let mut disconnected = context(104);
        disconnected.readiness.ssh_upstream_healthy = false;
        let mut data = syn.clone();
        assert_eq!(
            p.rewrite(new, disconnected, Leg::ApplicationToRelay, &mut data),
            Err(PipelineError::PolicyBlocked)
        );
        assert_eq!(p.active_records(), 0);
        assert_eq!(data, syn);
    }

    #[test]
    fn both_fins_retain_final_ack_but_rst_retires() {
        let original = tuple(true);
        let translated = alias(original);
        let syn = frame(original, 2);
        let mut p = setup();
        let ticket = p.begin(context(1), &syn, translated).unwrap();
        p.activate(ticket, context(2).owner, 2, true).unwrap();
        let mut fin = frame(original, 0x11);
        p.rewrite(ticket, context(3), Leg::ApplicationToRelay, &mut fin)
            .unwrap();
        let mut fin = frame(reverse(translated), 0x11);
        p.rewrite(ticket, context(4), Leg::RelayToApplication, &mut fin)
            .unwrap();
        assert_eq!(p.active_records(), 1);
        let mut ack = frame(original, 0x10);
        p.rewrite(ticket, context(5), Leg::ApplicationToRelay, &mut ack)
            .unwrap();
        let mut reset = frame(reverse(translated), 4);
        p.rewrite(ticket, context(6), Leg::RelayToApplication, &mut reset)
            .unwrap();
        assert_eq!(p.active_records(), 0);
    }
}
