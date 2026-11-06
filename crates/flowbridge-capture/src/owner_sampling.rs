//! Read-only NDISRD frame -> IP Helper candidate continuity observer.
//! A PID/creation epoch/path is sampled from the live Windows process object
//! and two fresh IP Helper tables, NOT from the frame. This is NOT PacketBound.
//! At most 24 tuples and identities exist transiently in memory; no PID, path,
//! tuple, payload, or endpoint is emitted or persisted in the report.

use crate::ndis_wire::Direction;
use flowbridge_core::ndis_frame_tcp::inspect_ethernet_tcp;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

pub(crate) const MAX_OWNER_SNAPSHOTS: u64 = 24;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcessCandidate {
    pub pid: u32,
    pub created_100ns: u64,
    pub path: String,
}

impl ProcessCandidate {
    fn valid(&self) -> bool {
        self.pid != 0 && self.created_100ns != 0 && !self.path.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Candidate {
    ConsistentSnapshot(ProcessCandidate),
    Missing,
    Uncertain,
}

#[derive(Debug)]
enum FlowHistory {
    Observed(ProcessCandidate),
    Quarantined,
}

#[derive(Default, Debug)]
pub(crate) struct Sampler {
    frames_seen: u64,
    tcp_frames_eligible: u64,
    invalid_or_unsupported: u64,
    ipv6_scope_unknown: u64,
    snapshot_budget_skipped: u64,
    snapshot_queries: u64,
    consistent_candidates: u64,
    candidates_missing: u64,
    candidates_uncertain: u64,
    changed_owner_same_tuple: u64,
    disappeared_owner_same_tuple: u64,
    indeterminate_owner_same_tuple: u64,
    invalid_owner_identity: u64,
    quarantined_reobservations: u64,
    missing_initial_syn_quarantined: u64,
    first_syn_without_owner_quarantined: u64,
    // A read-only, bounded, in-process diagnostic. Never an authority token.
    flow_history: HashMap<(SocketAddr, SocketAddr), FlowHistory>,
}

impl Sampler {
    fn quarantine_unproven_first_syn(&mut self, key: (SocketAddr, SocketAddr)) {
        if let std::collections::hash_map::Entry::Vacant(slot) = self.flow_history.entry(key) {
            slot.insert(FlowHistory::Quarantined);
            self.first_syn_without_owner_quarantined =
                self.first_syn_without_owner_quarantined.saturating_add(1);
        }
    }

    fn quarantine_existing(&mut self, key: (SocketAddr, SocketAddr)) -> bool {
        if matches!(self.flow_history.get(&key), Some(FlowHistory::Observed(_))) {
            self.flow_history.insert(key, FlowHistory::Quarantined);
            true
        } else {
            false
        }
    }

    /// Never admits a packet to policy. The callback is a query-only OS probe;
    /// it cannot produce a PacketBound witness or authorize selected traffic.
    pub(crate) fn observe(
        &mut self,
        direction: Direction,
        frame: &[u8],
        mut lookup: impl FnMut(SocketAddr, SocketAddr) -> Candidate,
    ) {
        self.frames_seen = self.frames_seen.saturating_add(1);
        let packet = match inspect_ethernet_tcp(frame) {
            Ok(p) => p,
            Err(_) => {
                self.invalid_or_unsupported = self.invalid_or_unsupported.saturating_add(1);
                return;
            }
        };
        self.tcp_frames_eligible = self.tcp_frames_eligible.saturating_add(1);
        let key = match direction {
            Direction::ToAdapter => (packet.tcp.tuple.source, packet.tcp.tuple.destination),
            Direction::ToStack => (packet.tcp.tuple.destination, packet.tcp.tuple.source),
        };
        if [key.0, key.1].iter().any(|addr| match addr {
            SocketAddr::V6(v6) => v6.ip().is_unicast_link_local(),
            SocketAddr::V4(_) => false,
        }) {
            self.ipv6_scope_unknown = self.ipv6_scope_unknown.saturating_add(1);
            return;
        }
        // Once a tuple is ambiguous it must NEVER recover by observing a
        // later same-tuple packet: that could be an unrelated recycled flow.
        if matches!(self.flow_history.get(&key), Some(FlowHistory::Quarantined)) {
            self.quarantined_reobservations = self.quarantined_reobservations.saturating_add(1);
            return;
        }
        if !self.flow_history.contains_key(&key) {
            // Bound the actual quarantine ledger as well as IP Helper calls.
            if self.flow_history.len() >= MAX_OWNER_SNAPSHOTS as usize {
                self.snapshot_budget_skipped = self.snapshot_budget_skipped.saturating_add(1);
                return;
            }
            let ip = &frame[packet.region.offset..packet.region.offset + packet.region.length];
            let tcp_start = if ip[0] >> 4 == 4 {
                usize::from(ip[0] & 15) * 4
            } else {
                40
            };
            let flags = ip[tcp_start + 13];
            // An inbound packet, ACK/data, SYN+ACK or FIN cannot establish
            // outbound flow provenance, even as a read-only candidate.
            let initial_outbound_syn = direction == Direction::ToAdapter && (flags & 0x1f) == 0x02;
            if !initial_outbound_syn {
                self.flow_history.insert(key, FlowHistory::Quarantined);
                self.missing_initial_syn_quarantined =
                    self.missing_initial_syn_quarantined.saturating_add(1);
                return;
            }
        }
        if self.snapshot_queries >= MAX_OWNER_SNAPSHOTS {
            self.snapshot_budget_skipped = self.snapshot_budget_skipped.saturating_add(1);
            return;
        }
        self.snapshot_queries += 1;
        match lookup(key.0, key.1) {
            Candidate::ConsistentSnapshot(identity) if identity.valid() => {
                match self.flow_history.get(&key) {
                    None => {
                        self.flow_history
                            .insert(key, FlowHistory::Observed(identity));
                        self.consistent_candidates += 1;
                    }
                    Some(FlowHistory::Observed(previous)) if previous == &identity => {
                        self.consistent_candidates += 1;
                    }
                    Some(FlowHistory::Observed(_)) => {
                        self.flow_history.insert(key, FlowHistory::Quarantined);
                        self.changed_owner_same_tuple += 1;
                    }
                    Some(FlowHistory::Quarantined) => {
                        self.quarantined_reobservations += 1;
                    }
                }
            }
            Candidate::ConsistentSnapshot(_) => {
                self.invalid_owner_identity += 1;
                self.candidates_uncertain += 1;
                if self.quarantine_existing(key) {
                    self.indeterminate_owner_same_tuple += 1;
                } else {
                    self.quarantine_unproven_first_syn(key);
                }
            }
            Candidate::Missing => {
                self.candidates_missing += 1;
                if self.quarantine_existing(key) {
                    self.disappeared_owner_same_tuple += 1;
                } else {
                    self.quarantine_unproven_first_syn(key);
                }
            }
            Candidate::Uncertain => {
                self.candidates_uncertain += 1;
                if self.quarantine_existing(key) {
                    self.indeterminate_owner_same_tuple += 1;
                } else {
                    self.quarantine_unproven_first_syn(key);
                }
            }
        }
    }

    pub(crate) fn report(&self) -> Value {
        json!({
            "requested": true,
            "mode": "NDISRD_LISTEN_BOTH_copy_only",
            "max_iphelper_queries": MAX_OWNER_SNAPSHOTS,
            "frames_seen": self.frames_seen,
            "tcp_frames_eligible": self.tcp_frames_eligible,
            "invalid_or_unsupported": self.invalid_or_unsupported,
            "ipv6_scope_unknown": self.ipv6_scope_unknown,
            "snapshot_budget_skipped": self.snapshot_budget_skipped,
            "snapshot_queries": self.snapshot_queries,
            "two_snapshot_process_candidates": self.consistent_candidates,
            "candidate_not_present": self.candidates_missing,
            "candidate_indeterminate": self.candidates_uncertain,
            "same_tuple_pid_epoch_or_path_changed": self.changed_owner_same_tuple,
            "same_tuple_owner_disappeared": self.disappeared_owner_same_tuple,
            "same_tuple_owner_indeterminate": self.indeterminate_owner_same_tuple,
            "invalid_process_candidate": self.invalid_owner_identity,
            "quarantined_reobservations": self.quarantined_reobservations,
            "missing_initial_syn_quarantined": self.missing_initial_syn_quarantined,
            "first_syn_without_owner_quarantined": self.first_syn_without_owner_quarantined,
            "tracked_candidate_tuples": self.flow_history.len(),
            "bounded_ephemeral_candidate_ledger": true,
            "kernel_packet_owner_witness_available": false,
            "packet_owner_bound": false,
            "native_packet_attribution_proved": false,
            "authorizes_capture": false,
            "protected_redirect_available": false,
            "identity_and_endpoints_saved": false,
            "packet_payload_saved": false
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_pipeline::tests::{frame, tuple};

    fn owner(pid: u32, created_100ns: u64) -> Candidate {
        Candidate::ConsistentSnapshot(ProcessCandidate {
            pid,
            created_100ns,
            path: r"C:\Private\app.exe".into(),
        })
    }

    #[test]
    fn outgoing_and_incoming_queries_have_local_remote_order_without_authority() {
        let t = tuple(false);
        let packet = frame(t, 0x02);
        let mut sample = Sampler::default();
        sample.observe(Direction::ToAdapter, &packet, |local, remote| {
            assert_eq!((local, remote), (t.source, t.destination));
            owner(47, 900)
        });
        // The inbound SYN+ACK reverses the wire tuple, but retains the
        // original local->remote candidate ledger key.
        let inbound = frame(
            flowbridge_core::tcp_packet::TcpTuple {
                source: t.destination,
                destination: t.source,
            },
            0x12,
        );
        sample.observe(Direction::ToStack, &inbound, |local, remote| {
            assert_eq!((local, remote), (t.source, t.destination));
            Candidate::Missing
        });
        let result = sample.report();
        assert_eq!(result["snapshot_queries"], 2);
        assert_eq!(result["two_snapshot_process_candidates"], 1);
        assert_eq!(result["candidate_not_present"], 1);
        assert_eq!(result["packet_owner_bound"], false);
        assert_eq!(result["authorizes_capture"], false);
        assert_eq!(result["identity_and_endpoints_saved"], false);
        assert!(!result.to_string().contains("Private"));
        assert!(!result.to_string().contains("192.0.2.1"));
    }

    #[test]
    fn malformed_frames_never_query_and_budget_is_strict() {
        let mut sample = Sampler::default();
        sample.observe(Direction::ToAdapter, &[0; 13], |_, _| {
            panic!("malformed frame reached IP Helper")
        });
        for n in 0..MAX_OWNER_SNAPSHOTS + 8 {
            let mut t = tuple(true);
            t.source.set_port(40001 + n as u16);
            let packet = frame(t, 0x02);
            sample.observe(Direction::ToAdapter, &packet, |local, remote| {
                assert_eq!((local, remote), (t.source, t.destination));
                Candidate::Uncertain
            });
        }
        let report = sample.report();
        assert_eq!(report["snapshot_queries"], MAX_OWNER_SNAPSHOTS);
        assert_eq!(report["snapshot_budget_skipped"], 8);
        assert_eq!(report["invalid_or_unsupported"], 1);
        assert_eq!(report["candidate_indeterminate"], MAX_OWNER_SNAPSHOTS);
        assert_eq!(report["native_packet_attribution_proved"], false);
    }

    #[test]
    fn syn_before_owner_and_unprepared_midstream_flow_never_gain_candidate() {
        for ipv6 in [false, true] {
            let t = tuple(ipv6);
            let mut sample = Sampler::default();
            // The first observable packet is an ACK, not the originating SYN.
            sample.observe(Direction::ToAdapter, &frame(t, 0x10), |_, _| {
                panic!("midstream packet queried IP Helper")
            });
            sample.observe(Direction::ToAdapter, &frame(t, 0x02), |_, _| {
                panic!("late SYN upgraded quarantined flow")
            });
            let report = sample.report();
            assert_eq!(report["missing_initial_syn_quarantined"], 1);
            assert_eq!(report["quarantined_reobservations"], 1);
            assert_eq!(report["snapshot_queries"], 0);
            assert_eq!(report["two_snapshot_process_candidates"], 0);

            let mut sample = Sampler::default();
            sample.observe(Direction::ToAdapter, &frame(t, 0x02), |_, _| {
                Candidate::Missing
            });
            sample.observe(Direction::ToAdapter, &frame(t, 0x10), |_, _| {
                panic!("late owner resurrected a failed first SYN")
            });
            let report = sample.report();
            assert_eq!(report["first_syn_without_owner_quarantined"], 1);
            assert_eq!(report["quarantined_reobservations"], 1);
            assert_eq!(report["snapshot_queries"], 1);
            assert_eq!(report["two_snapshot_process_candidates"], 0);

            let mut sample = Sampler::default();
            let inbound = frame(
                flowbridge_core::tcp_packet::TcpTuple {
                    source: t.destination,
                    destination: t.source,
                },
                0x12,
            );
            sample.observe(Direction::ToStack, &inbound, |_, _| {
                panic!("unprepared inbound packet queried IP Helper")
            });
            sample.observe(Direction::ToAdapter, &frame(t, 0x02), |_, _| {
                panic!("late outbound SYN resurrected inbound-only flow")
            });
            assert_eq!(sample.report()["missing_initial_syn_quarantined"], 1);
            assert_eq!(sample.report()["packet_owner_bound"], false);
        }
    }

    #[test]
    fn reused_tuple_changed_pid_or_epoch_is_quarantined_without_recovery() {
        for changed in [owner(48, 900), owner(47, 901)] {
            let t = tuple(false);
            let packet = frame(t, 0x02);
            let mut sample = Sampler::default();
            sample.observe(Direction::ToAdapter, &packet, |_, _| owner(47, 900));
            sample.observe(Direction::ToAdapter, &packet, |_, _| changed.clone());
            sample.observe(Direction::ToAdapter, &packet, |_, _| owner(47, 900));
            let report = sample.report();
            assert_eq!(report["two_snapshot_process_candidates"], 1);
            assert_eq!(report["same_tuple_pid_epoch_or_path_changed"], 1);
            assert_eq!(report["quarantined_reobservations"], 1);
            assert_eq!(report["tracked_candidate_tuples"], 1);
            assert_eq!(report["authorizes_capture"], false);
        }
    }

    #[test]
    fn missing_or_ambiguous_owner_poisoned_after_positive_read() {
        for gap in [Candidate::Missing, Candidate::Uncertain] {
            let t = tuple(true);
            let packet = frame(t, 0x02);
            let mut sample = Sampler::default();
            sample.observe(Direction::ToAdapter, &packet, |_, _| owner(47, 900));
            sample.observe(Direction::ToAdapter, &packet, |_, _| gap.clone());
            sample.observe(Direction::ToAdapter, &packet, |_, _| owner(47, 900));
            let report = sample.report();
            assert_eq!(report["quarantined_reobservations"], 1);
            assert_eq!(
                report["same_tuple_owner_disappeared"].as_u64().unwrap()
                    + report["same_tuple_owner_indeterminate"].as_u64().unwrap(),
                1
            );
            assert_eq!(report["packet_owner_bound"], false);
        }
    }

    #[test]
    fn different_connections_remain_isolated_and_invalid_identity_never_counts() {
        let first = tuple(false);
        let mut second = tuple(false);
        second.source.set_port(42001);
        let mut sample = Sampler::default();
        sample.observe(Direction::ToAdapter, &frame(first, 0x02), |_, _| {
            owner(47, 900)
        });
        sample.observe(Direction::ToAdapter, &frame(second, 0x02), |_, _| {
            owner(48, 901)
        });
        sample.observe(Direction::ToAdapter, &frame(first, 0x02), |_, _| {
            Candidate::ConsistentSnapshot(ProcessCandidate {
                pid: 0,
                created_100ns: 900,
                path: String::new(),
            })
        });
        let report = sample.report();
        assert_eq!(report["two_snapshot_process_candidates"], 2);
        assert_eq!(report["invalid_process_candidate"], 1);
        assert_eq!(report["same_tuple_owner_indeterminate"], 1);
        assert_eq!(report["tracked_candidate_tuples"], 2);
        assert_eq!(report["protected_redirect_available"], false);
    }
}
