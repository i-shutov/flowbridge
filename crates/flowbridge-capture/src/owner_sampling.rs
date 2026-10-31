//! Strictly read-only correlation of a copied NDISRD frame tuple to
//! Windows IP Helper's *two-snapshot process candidate*. It is NOT PacketBound.
//! No PID, executable path, IP address, port, or frame bytes are retained.

use crate::ndis_wire::Direction;
use flowbridge_core::ndis_frame_tcp::inspect_ethernet_tcp;
use serde_json::{json, Value};
use std::net::SocketAddr;

pub(crate) const MAX_OWNER_SNAPSHOTS: u64 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Candidate {
    ConsistentSnapshot,
    Missing,
    Uncertain,
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
}

impl Sampler {
    /// Never admits a packet to the policy pipeline. Source/destination are
    /// temporary, passed only to a query-only callback and then discarded.
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
        // Incoming wire endpoints reverse relative to an application's local
        // socket. TCP ownership lookup always asks for (local, remote).
        let (local, remote) = match direction {
            Direction::ToAdapter => (packet.tcp.tuple.source, packet.tcp.tuple.destination),
            Direction::ToStack => (packet.tcp.tuple.destination, packet.tcp.tuple.source),
        };
        // The Ethernet frame contains no IPv6 interface scope ID; never
        // manufacture one for a link-local tuple.
        if [local, remote].iter().any(|addr| match addr {
            SocketAddr::V6(v6) => v6.ip().is_unicast_link_local(),
            SocketAddr::V4(_) => false,
        }) {
            self.ipv6_scope_unknown = self.ipv6_scope_unknown.saturating_add(1);
            return;
        }
        if self.snapshot_queries >= MAX_OWNER_SNAPSHOTS {
            self.snapshot_budget_skipped = self.snapshot_budget_skipped.saturating_add(1);
            return;
        }
        self.snapshot_queries += 1;
        match lookup(local, remote) {
            Candidate::ConsistentSnapshot => self.consistent_candidates += 1,
            Candidate::Missing => self.candidates_missing += 1,
            Candidate::Uncertain => self.candidates_uncertain += 1,
        }
    }

    pub(crate) fn report(&self) -> Value {
        json!({
            "requested":true,
            "mode":"NDISRD_LISTEN_BOTH_copy_only",
            "max_iphelper_queries":MAX_OWNER_SNAPSHOTS,
            "frames_seen":self.frames_seen,
            "tcp_frames_eligible":self.tcp_frames_eligible,
            "invalid_or_unsupported":self.invalid_or_unsupported,
            "ipv6_scope_unknown":self.ipv6_scope_unknown,
            "snapshot_budget_skipped":self.snapshot_budget_skipped,
            "snapshot_queries":self.snapshot_queries,
            "two_snapshot_process_candidates":self.consistent_candidates,
            "candidate_not_present":self.candidates_missing,
            "candidate_indeterminate":self.candidates_uncertain,
            "packet_owner_bound":false,
            "native_packet_attribution_proved":false,
            "authorizes_capture":false,
            "protected_redirect_available":false,
            "identity_and_endpoints_saved":false,
            "packet_payload_saved":false
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_pipeline::tests::{frame, tuple};

    #[test]
    fn outgoing_and_incoming_are_queried_in_local_remote_order_without_authority() {
        let t = tuple(false);
        let packet = frame(t, 0x02);
        let mut sample = Sampler::default();
        sample.observe(Direction::ToAdapter, &packet, |local, remote| {
            assert_eq!((local, remote), (t.source, t.destination));
            Candidate::ConsistentSnapshot
        });
        sample.observe(Direction::ToStack, &packet, |local, remote| {
            assert_eq!((local, remote), (t.destination, t.source));
            Candidate::Missing
        });
        let result = sample.report();
        assert_eq!(result["snapshot_queries"], 2);
        assert_eq!(result["two_snapshot_process_candidates"], 1);
        assert_eq!(result["candidate_not_present"], 1);
        assert_eq!(result["packet_owner_bound"], false);
        assert_eq!(result["authorizes_capture"], false);
        assert_eq!(result["identity_and_endpoints_saved"], false);
        assert!(!result.to_string().contains("127.0.0.1"));
    }

    #[test]
    fn malformed_frames_are_never_queried_and_budget_is_strict() {
        let t = tuple(true);
        let packet = frame(t, 0x02);
        let mut sample = Sampler::default();
        sample.observe(Direction::ToAdapter, &[0; 13], |_, _| {
            panic!("malformed frame reached IP Helper")
        });
        for _ in 0..MAX_OWNER_SNAPSHOTS + 8 {
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
}
