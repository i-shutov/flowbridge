//! R68 clean-room, *pure* Rust user-mode decision MODEL, not a kernel adapter.
//! No Windows FFI, networking, drivers, BFE operations, or security PASS.
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family { V4, V6 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope { OutsideTcp, NeitherSelected, RedirectOnly, AuthOnly, BothSelected }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inputs {
    pub family: Family,
    pub original_selected: bool,
    pub current_selected: bool,
    pub tcp: bool,
    pub endpoint_owner_selected: bool,
    pub metadata_complete: bool,
    pub epoch_match: bool,
    pub start_key_match: bool,
    pub endpoint_unique: bool,
    pub redirect_state_clean: bool,
    pub destination_valid: bool,
    pub target_pid_match: bool,
    pub redirected_flag: bool,
    pub ssh_ok: bool,
    pub wfp_ok: bool,
    pub owner_alive_observed: bool,
    pub auth_callback_observed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub scope: Scope,
    /// Conditional issuance: this code does not mint/attest a real WFP ticket.
    pub issue_candidate: bool,
    /// Conditional witness, not a real WFP callback or kernel-origin proof.
    pub auth_candidate: bool,
    /// Action requested in the own callback, not system-wide packet suppression.
    pub block_requested: bool,
    /// A ticket might be issued without selection by own AUTH filter.
    pub orphan_ticket: bool,
    /// Own AUTH filter may select a flow never redirected by our policy.
    pub auth_without_redirect: bool,
}

pub fn decide(input: Inputs) -> Outcome {
    let redirect_match = input.tcp && input.current_selected;
    let auth_match = input.tcp && input.original_selected;
    let scope = match (input.tcp, redirect_match, auth_match) {
        (false, _, _) => Scope::OutsideTcp,
        (true, false, false) => Scope::NeitherSelected,
        (true, true, false) => Scope::RedirectOnly,
        (true, false, true) => Scope::AuthOnly,
        (true, true, true) => Scope::BothSelected,
    };
    let issue_candidate = redirect_match
        && input.endpoint_owner_selected && input.metadata_complete
        && input.epoch_match && input.start_key_match && input.endpoint_unique
        && input.redirect_state_clean && input.destination_valid
        && input.ssh_ok && input.wfp_ok && input.owner_alive_observed;
    let auth_candidate = issue_candidate && auth_match && input.target_pid_match
        && input.redirected_flag && input.auth_callback_observed;
    Outcome {
        scope, issue_candidate, auth_candidate,
        block_requested: auth_match && input.auth_callback_observed && !auth_candidate,
        orphan_ticket: issue_candidate && !auth_match,
        auth_without_redirect: auth_match && input.auth_callback_observed && !redirect_match,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good(family: Family) -> Inputs {
        Inputs { family, original_selected: true, current_selected: true, tcp: true,
            endpoint_owner_selected: true, metadata_complete: true,
            epoch_match: true, start_key_match: true, endpoint_unique: true,
            redirect_state_clean: true, destination_valid: true,
            target_pid_match: true, redirected_flag: true,
            ssh_ok: true, wfp_ok: true, owner_alive_observed: true,
            auth_callback_observed: true }
    }
    #[test] fn selected_v4_v6_are_model_candidates_only() {
        for f in [Family::V4, Family::V6] {
            let d = decide(good(f));
            assert_eq!(d.scope, Scope::BothSelected);
            assert!(d.issue_candidate && d.auth_candidate);
            assert!(!d.block_requested);
        }
    }
    #[test] fn foreign_current_selected_original_auth_without_redirect() {
        for f in [Family::V4, Family::V6] {
            let mut s=good(f);s.current_selected=false;
            let d=decide(s);assert_eq!(d.scope,Scope::AuthOnly);
            assert!(!d.issue_candidate && !d.auth_candidate);
            assert!(d.block_requested && d.auth_without_redirect);
        }
    }
    #[test] fn selected_current_foreign_original_issues_orphan() {
        for f in [Family::V4, Family::V6] {
            let mut s=good(f);s.original_selected=false;
            let d=decide(s);assert_eq!(d.scope,Scope::RedirectOnly);
            assert!(d.issue_candidate && d.orphan_ticket);
            assert!(!d.auth_candidate && !d.block_requested);
        }
    }
    #[test] fn sibling_is_outside_selected_scope_not_permitted() {
        let mut s=good(Family::V4);s.original_selected=false;s.current_selected=false;
        let d=decide(s);assert_eq!(d.scope,Scope::NeitherSelected);
        assert!(!d.issue_candidate && !d.auth_candidate && !d.block_requested);
    }
    #[test] fn udp_and_quic_outside_tcp_scope() {
        let mut s=good(Family::V6);s.tcp=false;
        let d=decide(s);assert_eq!(d.scope,Scope::OutsideTcp);
        assert!(!d.issue_candidate && !d.auth_candidate);
    }
    #[test] fn pid_reuse_epoch_mismatch_rejected() {
        let mut s=good(Family::V4);s.epoch_match=false;
        let d=decide(s);assert!(!d.issue_candidate && !d.auth_candidate);
        assert!(d.block_requested);
    }
    #[test] fn different_start_key_rejected() {
        let mut s=good(Family::V6);s.start_key_match=false;
        assert!(!decide(s).auth_candidate);
    }
    #[test] fn endpoint_aba_rejected() {
        let mut s=good(Family::V4);s.endpoint_unique=false;
        assert!(!decide(s).issue_candidate);
    }
    #[test] fn redirect_by_other_not_unconditionally_trusted() {
        let mut s=good(Family::V6);s.redirect_state_clean=false;
        assert!(!decide(s).issue_candidate);
    }
    #[test] fn missing_auth_callback_is_not_block_proof() {
        let mut s=good(Family::V4);s.auth_callback_observed=false;
        let d=decide(s);assert!(d.issue_candidate);
        assert!(!d.auth_candidate && !d.block_requested);
    }
    #[test] fn missing_redirected_flag_rejects_auth() {
        let mut s=good(Family::V4);s.redirected_flag=false;
        assert!(!decide(s).auth_candidate);
    }
    #[test] fn local_target_pid_mismatch_rejects_auth() {
        let mut s=good(Family::V6);s.target_pid_match=false;
        assert!(!decide(s).auth_candidate);
    }
    #[test] fn unavailable_wfp_and_ssh_never_issues_ticket() {
        let mut s=good(Family::V4);s.wfp_ok=false;
        assert!(!decide(s).issue_candidate);
        s.wfp_ok=true;s.ssh_ok=false;
        assert!(!decide(s).issue_candidate);
    }
    #[test] fn observed_process_exit_rejects() {
        let mut s=good(Family::V4);s.owner_alive_observed=false;
        assert!(!decide(s).issue_candidate);
    }
    #[test] fn metadata_or_destination_missing_rejects() {
        let mut s=good(Family::V6);s.metadata_complete=false;
        assert!(!decide(s).issue_candidate);
        s.metadata_complete=true;s.destination_valid=false;
        assert!(!decide(s).issue_candidate);
    }
    #[test] fn endpoint_owner_mismatch_rejects() {
        let mut s=good(Family::V4);s.endpoint_owner_selected=false;
        assert!(!decide(s).issue_candidate);
    }
}
