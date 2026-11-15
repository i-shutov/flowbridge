//! R202 clean-room Rust value model of *documented* WFP dynamic-session lifetime.
//! No Win32/kernel/driver/WFP calls. Assumes only an exact selected-app TCP case;
//! does NOT decide Windows network disposition, DIRECT or actual leak behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family { V4, V6 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// Scoped policy exists, but native classify and SSH admission are unproved.
    PresentNotProven,
    /// The dynamic session has ended and its owned filters were removed.
    AbsentOwnedFilters,
    /// Rules may exist but are incomplete, out of scope, or callback status is unknown.
    NotEstablished,
    /// A foreign policy might deny, but its presence and efficacy are unknown.
    ExternalPolicyUnknown,
}
/// Represents four exact scoped rules: REDIRECT V4/V6 and AUTH V4/V6.
/// The session-owner process is not assumed to be the SSH broker process.
#[derive(Clone, Debug)]
pub struct Lease {
    dynamic_session_open: bool,
    owned: [bool; 4],
    kernel_callout_registered: bool,
    ssh_alive: bool,
}
impl Lease {
    pub fn fresh_dynamic() -> Self {
        Self {dynamic_session_open: true, owned:[true;4],
            kernel_callout_registered:true, ssh_alive:true}
    }
    pub fn owner_session_terminates(&mut self) {
        // Microsoft FWPM_SESSION_FLAG_DYNAMIC contract: all objects added in
        // this session are removed when the session ends (including owner exit).
        self.dynamic_session_open=false;
        self.owned=[false;4];
    }
    pub fn kernel_callout_unregistered(&mut self) {self.kernel_callout_registered=false;}
    pub fn ssh_lost(&mut self) {self.ssh_alive=false;}
    /// Inputs are scope assumptions, not evidence retrieved from Windows.
    pub fn evaluate(&self, family: Family, tcp: bool, external_guard: bool) -> Coverage {
        if external_guard {return Coverage::ExternalPolicyUnknown;}
        if !self.dynamic_session_open {return Coverage::AbsentOwnedFilters;}
        if !tcp || !self.kernel_callout_registered {return Coverage::NotEstablished;}
        let (redirect,auth)=match family { Family::V4=>(0,2), Family::V6=>(1,3) };
        if !(self.owned[redirect] && self.owned[auth]) {
            return Coverage::NotEstablished;
        }
        // SSH absence cannot be mapped to DENY solely from BFE object presence.
        // No native AUTH_CONNECT callback proof is available here.
        let _ = self.ssh_alive;
        Coverage::PresentNotProven
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn all_scoped_rules_present_still_not_proof() {
        let lease=Lease::fresh_dynamic();
        for family in [Family::V4,Family::V6] {
            assert_eq!(lease.evaluate(family,true,false),Coverage::PresentNotProven);
        }
    }
    #[test] fn owner_exit_removes_both_families_even_with_kernel_callout_registered() {
        let mut lease=Lease::fresh_dynamic();lease.owner_session_terminates();
        assert!(lease.kernel_callout_registered);
        for family in [Family::V4,Family::V6] {
            assert_eq!(lease.evaluate(family,true,false),Coverage::AbsentOwnedFilters);
        }
    }
    #[test] fn no_automatic_owned_block_after_owner_exit() {
        let mut lease=Lease::fresh_dynamic();lease.owner_session_terminates();
        assert_eq!(lease.evaluate(Family::V4,true,false),Coverage::AbsentOwnedFilters);
    }
    #[test] fn kernel_callout_registration_alone_never_adds_bfe_filters() {
        let mut lease=Lease::fresh_dynamic();lease.owner_session_terminates();
        assert_eq!(lease.evaluate(Family::V6,true,false),Coverage::AbsentOwnedFilters);
    }
    #[test] fn unrelated_external_policy_is_unknown_not_a_leak_claim() {
        let mut lease=Lease::fresh_dynamic();lease.owner_session_terminates();
        assert_eq!(lease.evaluate(Family::V4,true,true),Coverage::ExternalPolicyUnknown);
    }
    #[test] fn udp_dns_quic_not_scoped_by_tcp_only_filters() {
        let lease=Lease::fresh_dynamic();
        assert_eq!(lease.evaluate(Family::V4,false,false),Coverage::NotEstablished);
        assert_eq!(lease.evaluate(Family::V6,false,false),Coverage::NotEstablished);
    }
    #[test] fn ssh_loss_while_filters_present_does_not_prove_deny() {
        let mut lease=Lease::fresh_dynamic();lease.ssh_lost();
        assert_eq!(lease.evaluate(Family::V4,true,false),Coverage::PresentNotProven);
    }
    #[test] fn no_kernel_registration_still_no_verified_owned_enforcement() {
        let mut lease=Lease::fresh_dynamic();lease.kernel_callout_unregistered();
        assert_eq!(lease.evaluate(Family::V6,true,false),Coverage::NotEstablished);
    }
}
