//! Standalone, dependency-free, PURE MODEL of what a future authorized WFP
//! redirect adapter would have to demonstrate before admitting a TCP stream.
//!
//! NOT a driver, callout, filter, BFE session, socket hook, proxy or security
//! boundary. None of these structs prove kernel origin: the real adapter MUST
//! get an accepted-socket-bound WFP record/context from Windows itself.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// Hypothetical evidence directly bound to an ALE connect-redirect callout.
    /// This flag cannot be accepted from an arbitrary user-mode caller.
    OwnedKernelRedirect,
    Etw,
    IpHelper,
    SocketTuple,
    UntrustedClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectState {
    NotRedirected,
    RedirectedBySelf,
    PreviouslyRedirectedBySelf,
    RedirectedByOther,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub pid: u32,
    /// Windows kernel process creation time captured from the *same referenced
    /// process object*; PID+time queried later does not prove historical owner.
    pub creation_time_100ns: u64,
    /// Opaque WFP app-id bytes. Exact matching is NOT basename/string matching.
    pub app_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capture {
    pub source: Source,
    /// An owned redirect-session generation; never inferred from a 5-tuple.
    pub session: u128,
    /// Unique ticket generated at classify and delivered through redirect context.
    /// It is NOT a documented WFP connection-id API by itself.
    pub ticket: u128,
    pub identity: Identity,
    pub original: SocketAddr,
    pub transport: Transport,
    pub redirect_state: RedirectState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accepted {
    /// Hypothetical immutable snapshot read from the original *accepted socket*.
    pub captured: Capture,
    pub records_from_accepted_socket: bool,
    pub context_from_accepted_socket: bool,
    pub owned_redirect_handle_confirmed: bool,
    /// A WFP record/context result from some other socket is not good enough.
    pub accepted_socket_binding_confirmed: bool,
    /// Required for loop/coexistence tracking before the first outbound connect.
    pub outbound_records_set_before_connect: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Health {
    /// Independent proof of active WFP enforcement is still required in a real
    /// implementation. A user-mode boolean is not kernel enforcement evidence.
    pub owned_filter_enforced: bool,
    pub callout_available: bool,
    pub tunnel_ready: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Model admission only, never a claim of WFP or packet-level PASS.
    RouteOnOwnedProxySocket,
    /// Ingress can be rejected; says nothing about sibling/unhooked DIRECT.
    RejectOwnedIngress,
    /// No evidence that the OS prevented DIRECT while WFP was unavailable.
    UnprotectedByWfp,
    /// Different full AppId: outside per-application selection, not a leak test.
    OutsideSelectedApp,
    /// UDP/QUIC/DNS/ICMP are not covered by a TCP-only redirect design.
    TransportNotCovered,
}

#[derive(Debug)]
pub struct TrustGate {
    session: u128,
    selected_app_id: Vec<u8>,
    consumed: HashSet<u128>,
}

/// No eviction: an evicted used ticket could be replayed. A full gate rejects
/// additional flows until a new controlled redirect session is established.
const MAX_TICKETS_PER_SESSION: usize = 4096;

impl TrustGate {
    pub fn new(session: u128, selected_app_id: Vec<u8>) -> Self {
        Self { session, selected_app_id, consumed: HashSet::new() }
    }

    pub fn decide(&mut self, classify: &Capture, accepted: &Accepted, health: Health) -> Verdict {
        if !health.owned_filter_enforced || !health.callout_available {
            return Verdict::UnprotectedByWfp;
        }
        if classify.transport != Transport::Tcp {
            return Verdict::TransportNotCovered;
        }
        if classify.identity.app_id != self.selected_app_id {
            return Verdict::OutsideSelectedApp;
        }
        if classify.source != Source::OwnedKernelRedirect
            || classify.session == 0
            || classify.session != self.session
            || classify.ticket == 0
            || classify.redirect_state != RedirectState::NotRedirected
            || classify.identity.pid == 0
            || classify.identity.creation_time_100ns == 0
            || classify.identity.app_id.is_empty()
            || classify.original.port() == 0
            || classify.original.ip().is_unspecified()
            || accepted.captured != *classify
            || !accepted.records_from_accepted_socket
            || !accepted.context_from_accepted_socket
            || !accepted.owned_redirect_handle_confirmed
            || !accepted.accepted_socket_binding_confirmed
            || !accepted.outbound_records_set_before_connect
        {
            return Verdict::RejectOwnedIngress;
        }
        if !health.tunnel_ready {
            return Verdict::RejectOwnedIngress;
        }
        if self.consumed.len() >= MAX_TICKETS_PER_SESSION {
            return Verdict::RejectOwnedIngress;
        }
        if !self.consumed.insert(classify.ticket) {
            return Verdict::RejectOwnedIngress;
        }
        Verdict::RouteOnOwnedProxySocket
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &[u8] = b"opaque-app-id-for-C:\\Apps\\A\\probe.exe";
    const SIBLING: &[u8] = b"opaque-app-id-for-D:\\Other\\probe.exe";
    const SESSION: u128 = 0xBAA1;

    fn capture(ipv6: bool, ticket: u128) -> Capture {
        Capture {
            source: Source::OwnedKernelRedirect,
            session: SESSION,
            ticket,
            identity: Identity {
                pid: 510,
                creation_time_100ns: 133_000_000_000,
                app_id: APP.to_vec(),
            },
            original: (if ipv6 { "[2001:db8::1]:443" } else { "192.0.2.10:443" })
                .parse().unwrap(),
            transport: Transport::Tcp,
            redirect_state: RedirectState::NotRedirected,
        }
    }
    fn accepted(c: &Capture) -> Accepted {
        Accepted {
            captured: c.clone(),
            records_from_accepted_socket: true,
            context_from_accepted_socket: true,
            owned_redirect_handle_confirmed: true,
            accepted_socket_binding_confirmed: true,
            outbound_records_set_before_connect: true,
        }
    }
    fn healthy() -> Health {
        Health { owned_filter_enforced: true, callout_available: true, tunnel_ready: true }
    }
    fn gate() -> TrustGate { TrustGate::new(SESSION, APP.to_vec()) }
    fn check(c: &Capture, a: &Accepted) -> Verdict { gate().decide(c, a, healthy()) }

    #[test]
    fn happy_tcp_ipv4_and_ipv6_are_only_conditional_model_admissions() {
        for ipv6 in [false, true] {
            let c = capture(ipv6, 1);
            assert_eq!(check(&c, &accepted(&c)), Verdict::RouteOnOwnedProxySocket);
        }
    }
    #[test]
    fn source_etw_iphelper_tuple_or_client_never_promotes_to_kernel_proof() {
        for source in [Source::Etw, Source::IpHelper, Source::SocketTuple, Source::UntrustedClient] {
            let mut c = capture(false, 2);
            c.source = source;
            assert_eq!(check(&c, &accepted(&c)), Verdict::RejectOwnedIngress);
        }
    }
    #[test]
    fn missing_record_context_handle_or_socket_binding_rejected() {
        let c = capture(false, 3);
        let mut a = accepted(&c);
        a.records_from_accepted_socket = false;
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
        let mut a = accepted(&c);
        a.context_from_accepted_socket = false;
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
        let mut a = accepted(&c);
        a.owned_redirect_handle_confirmed = false;
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
        let mut a = accepted(&c);
        a.accepted_socket_binding_confirmed = false;
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
        let mut a = accepted(&c);
        a.outbound_records_set_before_connect = false;
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
    }
    #[test]
    fn pid_reuse_different_creation_epoch_rejected_even_with_same_tuple() {
        let c = capture(false, 4);
        let mut a = accepted(&c);
        a.captured.identity.creation_time_100ns += 1;
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
    }
    #[test]
    fn forged_app_identity_or_same_basename_sibling_rejected() {
        let c = capture(false, 5);
        let mut a = accepted(&c);
        a.captured.identity.app_id = SIBLING.to_vec();
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
        let mut sibling = c.clone();
        sibling.identity.app_id = SIBLING.to_vec();
        assert_eq!(check(&sibling, &accepted(&sibling)), Verdict::OutsideSelectedApp);
    }
    #[test]
    fn modified_original_ip_port_or_family_rejected() {
        let c = capture(false, 6);
        let mut a = accepted(&c);
        a.captured.original = "192.0.2.11:443".parse().unwrap();
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
        let mut a = accepted(&c);
        a.captured.original = "192.0.2.10:8443".parse().unwrap();
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
        let mut a = accepted(&c);
        a.captured.original = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
    }
    #[test]
    fn capture_ticket_swapping_rejected_even_if_5tuple_unchanged() {
        let c = capture(false, 7);
        let mut a = accepted(&c);
        a.captured.ticket = 8;
        assert_eq!(check(&c, &a), Verdict::RejectOwnedIngress);
    }
    #[test]
    fn two_distinct_tickets_may_have_same_5tuple_without_being_merged() {
        let c1 = capture(false, 9);
        let c2 = capture(false, 10);
        assert_eq!(c1.original, c2.original);
        let mut gate = gate();
        assert_eq!(gate.decide(&c1, &accepted(&c1), healthy()), Verdict::RouteOnOwnedProxySocket);
        assert_eq!(gate.decide(&c2, &accepted(&c2), healthy()), Verdict::RouteOnOwnedProxySocket);
    }
    #[test]
    fn same_ticket_replay_rejected_even_if_all_fields_match() {
        let c = capture(false, 11);
        let a = accepted(&c);
        let mut gate = gate();
        assert_eq!(gate.decide(&c, &a, healthy()), Verdict::RouteOnOwnedProxySocket);
        assert_eq!(gate.decide(&c, &a, healthy()), Verdict::RejectOwnedIngress);
    }
    #[test]
    fn old_session_or_zero_ticket_cannot_be_reused_after_restart() {
        let mut c = capture(false, 12);
        c.session = SESSION - 1;
        assert_eq!(check(&c, &accepted(&c)), Verdict::RejectOwnedIngress);
        let c = capture(false, 0);
        assert_eq!(check(&c, &accepted(&c)), Verdict::RejectOwnedIngress);
    }
    #[test]
    fn absent_kernel_process_epoch_pid_or_exact_app_id_rejects() {
        let mut c = capture(false, 13);
        c.identity.creation_time_100ns = 0;
        assert_eq!(check(&c, &accepted(&c)), Verdict::RejectOwnedIngress);
        let mut c = capture(false, 14);
        c.identity.pid = 0;
        assert_eq!(check(&c, &accepted(&c)), Verdict::RejectOwnedIngress);
        let mut c = capture(false, 15);
        c.identity.app_id.clear();
        // Empty AppId is not selected: not a successful identity assertion.
        assert_eq!(check(&c, &accepted(&c)), Verdict::OutsideSelectedApp);
    }
    #[test]
    fn no_kernel_filter_or_callout_is_unprotected_not_system_fail_closed() {
        let c = capture(false, 16);
        let a = accepted(&c);
        let mut health = healthy();
        health.owned_filter_enforced = false;
        assert_eq!(gate().decide(&c, &a, health), Verdict::UnprotectedByWfp);
        health = healthy();
        health.callout_available = false;
        assert_eq!(gate().decide(&c, &a, health), Verdict::UnprotectedByWfp);
    }
    #[test]
    fn lost_ssh_denies_owned_ingress_only_not_sibling_direct() {
        let c = capture(false, 17);
        let mut health = healthy();
        health.tunnel_ready = false;
        assert_eq!(gate().decide(&c, &accepted(&c), health), Verdict::RejectOwnedIngress);
        let mut sibling = capture(false, 18);
        sibling.identity.app_id = SIBLING.to_vec();
        assert_eq!(gate().decide(&sibling, &accepted(&sibling), healthy()), Verdict::OutsideSelectedApp);
    }
    #[test]
    fn udp_quic_dns_and_icmp_not_covered_by_tcp_redirect() {
        for transport in [Transport::Udp, Transport::Icmp, Transport::Other] {
            let mut c = capture(false, 19);
            c.transport = transport;
            assert_eq!(check(&c, &accepted(&c)), Verdict::TransportNotCovered);
        }
    }
    #[test]
    fn proxy_loops_other_provider_and_previously_self_are_not_recaptured() {
        for redirect_state in [
            RedirectState::RedirectedBySelf,
            RedirectState::PreviouslyRedirectedBySelf,
            RedirectState::RedirectedByOther,
        ] {
            let mut c = capture(false, 22);
            c.redirect_state = redirect_state;
            assert_eq!(check(&c, &accepted(&c)), Verdict::RejectOwnedIngress);
        }
    }
    #[test]
    fn capacity_is_bounded_without_replay_permitting_eviction() {
        let mut g = gate();
        for ticket in 1..=MAX_TICKETS_PER_SESSION as u128 {
            let c = capture(false, ticket);
            assert_eq!(g.decide(&c, &accepted(&c), healthy()), Verdict::RouteOnOwnedProxySocket);
        }
        let extra = capture(false, 10_000);
        assert_eq!(g.decide(&extra, &accepted(&extra), healthy()), Verdict::RejectOwnedIngress);
        let replay = capture(false, 1);
        assert_eq!(g.decide(&replay, &accepted(&replay), healthy()), Verdict::RejectOwnedIngress);
    }
    #[test]
    fn missing_original_endpoint_refused() {
        let mut c = capture(false, 20);
        c.original = "0.0.0.0:443".parse().unwrap();
        assert_eq!(check(&c, &accepted(&c)), Verdict::RejectOwnedIngress);
        let mut c = capture(false, 21);
        c.original = "192.0.2.10:0".parse().unwrap();
        assert_eq!(check(&c, &accepted(&c)), Verdict::RejectOwnedIngress);
    }
}
