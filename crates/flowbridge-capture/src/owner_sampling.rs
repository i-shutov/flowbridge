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
struct ObservedFlow {
    identity: ProcessCandidate,
    // A repeated five-tuple with a different SYN ISN is a NEW connection,
    // even if IP Helper still reports the same PID / creation epoch / path.
    // This is an anti-reuse diagnostic, not an NDISRD ownership witness.
    initial_sequence: u32,
}

#[derive(Debug)]
enum FlowHistory {
    Observed(ObservedFlow),
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
    recycled_tuple_syn_quarantined: u64,
    terminal_fin_or_rst_quarantined: u64,
    exhausted_observed_tuple_quarantined: u64,
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
        // Even an exact PID/epoch/path match is insufficient across a
        // completed flow or a fresh initial sequence on a recycled 5-tuple.
        // These transitions happen BEFORE any potentially stale IP Helper
        // query; they can never be revived by a later snapshot.
        let ip = &frame[packet.region.offset..packet.region.offset + packet.region.length];
        let tcp_start = if ip[0] >> 4 == 4 {
            usize::from(ip[0] & 15) * 4
        } else {
            40
        };
        let flags = ip[tcp_start + 13];
        let initial_outbound_syn = direction == Direction::ToAdapter && (flags & 0x1f) == 0x02;
        let sequence = u32::from_be_bytes(
            ip[tcp_start + 4..tcp_start + 8]
                .try_into()
                .expect("validated TCP sequence bytes"),
        );
        if let Some(FlowHistory::Observed(previous)) = self.flow_history.get(&key) {
            if flags & 0x05 != 0 {
                // FIN/RST terminates diagnostic continuity: TIME_WAIT and
                // same-tuple reuse can never inherit the former candidate.
                self.flow_history.insert(key, FlowHistory::Quarantined);
                self.terminal_fin_or_rst_quarantined =
                    self.terminal_fin_or_rst_quarantined.saturating_add(1);
                return;
            }
            if direction == Direction::ToAdapter
                && flags & 0x02 != 0
                && (!initial_outbound_syn || previous.initial_sequence != sequence)
            {
                self.flow_history.insert(key, FlowHistory::Quarantined);
                self.recycled_tuple_syn_quarantined =
                    self.recycled_tuple_syn_quarantined.saturating_add(1);
                return;
            }
        }
        if !self.flow_history.contains_key(&key) {
            // Bound the actual quarantine ledger as well as IP Helper calls.
            if self.flow_history.len() >= MAX_OWNER_SNAPSHOTS as usize {
                self.snapshot_budget_skipped = self.snapshot_budget_skipped.saturating_add(1);
                return;
            }
            // An inbound packet, ACK/data, SYN+ACK or FIN cannot establish
            // outbound flow provenance, even as a read-only candidate.
            if !initial_outbound_syn {
                self.flow_history.insert(key, FlowHistory::Quarantined);
                self.missing_initial_syn_quarantined =
                    self.missing_initial_syn_quarantined.saturating_add(1);
                return;
            }
        }
        if self.snapshot_queries >= MAX_OWNER_SNAPSHOTS {
            // Do not leave an earlier positive candidate looking current when
            // it can no longer be revalidated; never issue a hidden retry.
            if self.quarantine_existing(key) {
                self.exhausted_observed_tuple_quarantined =
                    self.exhausted_observed_tuple_quarantined.saturating_add(1);
            }
            self.snapshot_budget_skipped = self.snapshot_budget_skipped.saturating_add(1);
            return;
        }
        self.snapshot_queries += 1;
        match lookup(key.0, key.1) {
            Candidate::ConsistentSnapshot(identity) if identity.valid() => {
                match self.flow_history.get(&key) {
                    None => {
                        self.flow_history.insert(
                            key,
                            FlowHistory::Observed(ObservedFlow {
                                identity,
                                initial_sequence: sequence,
                            }),
                        );
                        self.consistent_candidates += 1;
                    }
                    Some(FlowHistory::Observed(previous)) if previous.identity == identity => {
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
            "recycled_tuple_syn_quarantined": self.recycled_tuple_syn_quarantined,
            "terminal_fin_or_rst_quarantined": self.terminal_fin_or_rst_quarantined,
            "exhausted_observed_tuple_quarantined": self.exhausted_observed_tuple_quarantined,
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

    fn with_sequence(mut wire: Vec<u8>, initial_sequence: u32) -> Vec<u8> {
        // Re-checksum the complete IPv4/IPv6 TCP SYN fixture after changing
        // ISN; failure must exercise tuple recycling, not a malformed frame.
        let parsed = inspect_ethernet_tcp(&wire).unwrap();
        let start = parsed.region.offset;
        let ip_len = parsed.region.length;
        let ipv4 = wire[start] >> 4 == 4;
        let header_len = if ipv4 { 20 } else { 40 };
        let tcp = start + header_len;
        wire[tcp + 4..tcp + 8].copy_from_slice(&initial_sequence.to_be_bytes());
        wire[tcp + 16..tcp + 18].fill(0);
        let mut pseudo = Vec::new();
        if ipv4 {
            pseudo.extend_from_slice(&wire[start + 12..start + 20]);
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&((ip_len - header_len) as u16).to_be_bytes());
        } else {
            pseudo.extend_from_slice(&wire[start + 8..start + 40]);
            pseudo.extend_from_slice(&((ip_len - header_len) as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
        }
        pseudo.extend_from_slice(&wire[tcp..start + ip_len]);
        let mut sum = 0u32;
        for pair in pseudo.chunks(2) {
            sum += (u32::from(pair[0]) << 8) + u32::from(*pair.get(1).unwrap_or(&0));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        wire[tcp + 16..tcp + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        assert!(inspect_ethernet_tcp(&wire).is_ok());
        wire
    }

    #[test]
    fn same_tuple_new_isn_is_quarantined_even_when_pid_epoch_path_are_unchanged() {
        for ipv6 in [false, true] {
            let tuple = tuple(ipv6);
            let syn_a = with_sequence(frame(tuple, 0x02), 0x1020_3040);
            let syn_b = with_sequence(frame(tuple, 0x02), 0x1020_3041);
            let mut sampler = Sampler::default();
            sampler.observe(Direction::ToAdapter, &syn_a, |_, _| owner(47, 900));
            sampler.observe(Direction::ToAdapter, &syn_b, |_, _| {
                panic!("recycled tuple queried stale PID despite a changed ISN")
            });
            sampler.observe(Direction::ToAdapter, &syn_a, |_, _| {
                panic!("old SYN revived a recycled flow")
            });
            assert_eq!(sampler.report()["recycled_tuple_syn_quarantined"], 1);
            assert_eq!(sampler.report()["quarantined_reobservations"], 1);
            assert_eq!(sampler.report()["snapshot_queries"], 1);
            assert_eq!(sampler.report()["packet_owner_bound"], false);
        }
    }

    #[test]
    fn same_sequence_syn_retransmit_remains_only_a_candidate() {
        for ipv6 in [false, true] {
            let syn = with_sequence(frame(tuple(ipv6), 0x02), 0x1020_3040);
            let mut sampler = Sampler::default();
            sampler.observe(Direction::ToAdapter, &syn, |_, _| owner(47, 900));
            sampler.observe(Direction::ToAdapter, &syn, |_, _| owner(47, 900));
            assert_eq!(sampler.report()["two_snapshot_process_candidates"], 2);
            assert_eq!(sampler.report()["snapshot_queries"], 2);
            assert_eq!(sampler.report()["authorizes_capture"], false);
        }
    }

    #[test]
    fn fin_or_rst_ends_tuple_continuity_before_revalidation() {
        for ipv6 in [false, true] {
            for terminal in [0x01, 0x04] {
                let tuple = tuple(ipv6);
                let opposite = flowbridge_core::tcp_packet::TcpTuple {
                    source: tuple.destination,
                    destination: tuple.source,
                };
                let mut sampler = Sampler::default();
                sampler.observe(Direction::ToAdapter, &frame(tuple, 0x02), |_, _| {
                    owner(47, 900)
                });
                sampler.observe(
                    Direction::ToStack,
                    &frame(opposite, terminal | 0x10),
                    |_, _| panic!("terminal frame queried a potentially stale owner"),
                );
                sampler.observe(Direction::ToAdapter, &frame(tuple, 0x02), |_, _| {
                    panic!("same tuple restored candidate after FIN/RST")
                });
                assert_eq!(sampler.report()["terminal_fin_or_rst_quarantined"], 1);
                assert_eq!(sampler.report()["snapshot_queries"], 1);
                assert_eq!(sampler.report()["quarantined_reobservations"], 1);
            }
        }
    }

    #[test]
    fn snapshot_budget_exhaustion_invalidates_prior_positive_without_retry() {
        let first = tuple(false);
        let mut sampler = Sampler::default();
        sampler.observe(Direction::ToAdapter, &frame(first, 0x02), |_, _| {
            owner(47, 900)
        });
        for number in 1..MAX_OWNER_SNAPSHOTS {
            let mut next = first;
            next.source.set_port(40001 + number as u16);
            sampler.observe(Direction::ToAdapter, &frame(next, 0x02), |_, _| {
                owner(47, 900)
            });
        }
        sampler.observe(Direction::ToAdapter, &frame(first, 0x02), |_, _| {
            panic!("budget exhausted but queried owner")
        });
        sampler.observe(Direction::ToAdapter, &frame(first, 0x02), |_, _| {
            panic!("quarantined tuple queried owner")
        });
        let report = sampler.report();
        assert_eq!(report["snapshot_queries"], MAX_OWNER_SNAPSHOTS);
        assert_eq!(report["exhausted_observed_tuple_quarantined"], 1);
        assert_eq!(report["snapshot_budget_skipped"], 1);
        assert_eq!(report["quarantined_reobservations"], 1);
        assert_eq!(report["authorizes_capture"], false);
    }

    #[test]
    fn sibling_candidate_is_not_revoked_by_other_tuple_recycling() {
        for ipv6 in [false, true] {
            let first = tuple(ipv6);
            let mut second = first;
            second.source.set_port(41021);
            let mut sampler = Sampler::default();
            sampler.observe(Direction::ToAdapter, &frame(first, 0x02), |_, _| {
                owner(47, 900)
            });
            sampler.observe(Direction::ToAdapter, &frame(second, 0x02), |_, _| {
                owner(48, 901)
            });
            sampler.observe(
                Direction::ToAdapter,
                &with_sequence(frame(first, 0x02), 13),
                |_, _| panic!("recycling cannot requery stale tuple"),
            );
            sampler.observe(Direction::ToAdapter, &frame(second, 0x10), |_, _| {
                owner(48, 901)
            });
            assert_eq!(sampler.report()["two_snapshot_process_candidates"], 3);
            assert_eq!(sampler.report()["recycled_tuple_syn_quarantined"], 1);
            assert_eq!(sampler.report()["packet_owner_bound"], false);
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
