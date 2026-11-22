#![forbid(unsafe_code)]
//! R221: value-only model of a WFP AUTH callout versus later filter arbitration.
//! Synthetic inputs; not a callout, socket, driver, network probe or kernel proof.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family { V4, V6 }

#[derive(Clone, Copy, Debug)]
pub struct Case {
    pub family: Family,
    pub selected_original: bool,
    pub redirected: bool,
    pub same_endpoint_epoch: bool,
    pub later_veto: bool,
    pub same_broker_requestor: bool,
    /// This is a deliberately hypothetical input, not a way to read a blocked socket.
    pub exact_context_known: bool,
    pub actual_accepted_socket_receipt: bool,
}

/// The model assumes valid AppId encoding, original destination, protocol TCP,
/// initial action-write right, current metadata and an unspent native ticket.
/// These assumptions are NOT established by this value-level experiment.
pub fn r19_auth_candidate(c: Case) -> bool {
    let _family = c.family;
    c.selected_original && c.redirected && c.same_endpoint_epoch
}

/// WFP's published arbitration contract evaluates all sublayers; a later veto
/// may block even after a callout has issued a hard PERMIT candidate.
pub fn final_wfp_permit(c: Case) -> bool {
    r19_auth_candidate(c) && !c.later_veto
}

#[derive(Clone, Copy, Debug)]
pub struct OneShot {
    auth_seen: bool,
    live: bool,
}
impl OneShot {
    pub fn after_auth(c: Case) -> Self {
        Self { auth_seen: r19_auth_candidate(c), live: true }
    }
    /// R19 Book::take + ioctl(CLAIM) source boundary. No accepted SOCKET or
    /// final WFP result is an input. Calling this method is *not* a way to
    /// acquire context; availability of exact bytes is assumed by the caller.
    pub fn raw_kernel_claim(&mut self, c: Case) -> bool {
        if !self.live || !c.same_broker_requestor || !c.exact_context_known { return false; }
        self.live = false;
        self.auth_seen
    }
    /// Abstraction of the unchanged broker's accepted-socket-owned path.
    /// Real source uses WSAIoctl to query records/context on the accepted socket.
    pub fn typed_broker_claim(&mut self, c: Case) -> bool {
        if !final_wfp_permit(c) || !c.actual_accepted_socket_receipt { return false; }
        self.raw_kernel_claim(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good(family: Family) -> Case {
        Case { family, selected_original: true, redirected: true,
            same_endpoint_epoch: true, later_veto: false,
            same_broker_requestor: true, exact_context_known: true,
            actual_accepted_socket_receipt: true }
    }
    #[test] fn source_candidate_is_not_final_permit_v4_v6() {
        for f in [Family::V4, Family::V6] {
            let mut c=good(f);
            assert!(r19_auth_candidate(c));
            c.later_veto=true;
            assert!(r19_auth_candidate(c));
            assert!(!final_wfp_permit(c));
        }
    }
    #[test] fn kernel_claim_does_not_observe_later_veto() {
        for f in [Family::V4, Family::V6] {
            let c=good(f);
            let mut vetoed=c;vetoed.later_veto=true;
            // These are counterfactual calls with explicitly assumed exact bytes.
            assert!(OneShot::after_auth(c).raw_kernel_claim(c));
            assert!(OneShot::after_auth(vetoed).raw_kernel_claim(vetoed));
        }
    }
    #[test] fn typed_broker_cannot_claim_from_blocked_socket() {
        let mut c=good(Family::V4);c.later_veto=true;
        assert!(!OneShot::after_auth(c).typed_broker_claim(c));
    }
    #[test] fn typed_broker_requires_real_receipt() {
        let mut c=good(Family::V6);c.actual_accepted_socket_receipt=false;
        assert!(!OneShot::after_auth(c).typed_broker_claim(c));
    }
    #[test] fn one_shot_claim_consumed_on_success() {
        let c=good(Family::V4);let mut ticket=OneShot::after_auth(c);
        assert!(ticket.typed_broker_claim(c));
        assert!(!ticket.typed_broker_claim(c));
    }
    #[test] fn absent_exact_context_cannot_claim() {
        let mut c=good(Family::V4);let mut ticket=OneShot::after_auth(c);
        c.exact_context_known=false;assert!(!ticket.raw_kernel_claim(c));
        // No assertion about failed malformed claims: R19 can consume a matched
        // sequence even if other context bytes differ.
    }
    #[test] fn sibling_direct_or_pid_reuse_not_authenticated() {
        let mut c=good(Family::V6);c.redirected=false;
        assert!(!r19_auth_candidate(c));
        c.redirected=true;c.same_endpoint_epoch=false;
        assert!(!r19_auth_candidate(c));
    }
    #[test] fn wrong_broker_does_not_claim() {
        let mut c=good(Family::V4);c.same_broker_requestor=false;
        assert!(!OneShot::after_auth(c).raw_kernel_claim(c));
    }
}
