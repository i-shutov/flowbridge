//! R70 clean-room pure Rust offline decision model.
//! No WDK, FFI, unsafe, sockets, drivers, BFE operations, or side effects.
//! The bit positions are SYNTHETIC and are not WFP metadata constants.
//!
//! Compile locally: rustc --edition=2021 --test r70_guard.rs -o r70_test && ./r70_test

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Unobserved,
    MetadataMissing,
    RedirectFlagMissing,
    GuardDenied,
    ConditionalReceiptOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectResult {
    Unobserved,
    OutsideScope,
    HealthOrOwnerDenied,
    UnqueriedStateCandidate,
    StateNotClear,
    QueriedCleanCandidate,
}

const AUTH_REQUIRED_METADATA: u16 = 0b1111;
const AUTH_ALL_OBSERVABLE_GATES: u16 = (1 << 14) - 1;

pub fn auth(bits: u16) -> AuthResult {
    if bits & (1 << 13) == 0 { return AuthResult::Unobserved; }
    if bits & AUTH_REQUIRED_METADATA != AUTH_REQUIRED_METADATA {
        return AuthResult::MetadataMissing;
    }
    if bits & (1 << 4) == 0 { return AuthResult::RedirectFlagMissing; }
    if bits & AUTH_ALL_OBSERVABLE_GATES != AUTH_ALL_OBSERVABLE_GATES {
        return AuthResult::GuardDenied;
    }
    // Not proof of the original socket, historical process, sibling DIRECT or egress.
    AuthResult::ConditionalReceiptOnly
}

pub fn redirect(bits: u8) -> RedirectResult {
    if bits & 128 == 0 { return RedirectResult::Unobserved; }
    if bits & 12 != 12 { return RedirectResult::OutsideScope; }
    if bits & 48 != 48 { return RedirectResult::HealthOrOwnerDenied; }
    if bits & 1 == 0 { return RedirectResult::UnqueriedStateCandidate; }
    if bits & 2 == 0 { return RedirectResult::StateNotClear; }
    RedirectResult::QueriedCleanCandidate
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOOD: u16 = AUTH_ALL_OBSERVABLE_GATES;
    const ISSUE: u8 = 128 | 12 | 48;

    #[test] fn metadata_can_be_present_conditionally() {
        assert_eq!(auth(GOOD), AuthResult::ConditionalReceiptOnly);
    }
    #[test] fn missing_pid() { assert_eq!(auth(GOOD & !1), AuthResult::MetadataMissing); }
    #[test] fn missing_endpoint() { assert_eq!(auth(GOOD & !2), AuthResult::MetadataMissing); }
    #[test] fn missing_target_pid() { assert_eq!(auth(GOOD & !4), AuthResult::MetadataMissing); }
    #[test] fn missing_original_dest() { assert_eq!(auth(GOOD & !8), AuthResult::MetadataMissing); }
    #[test] fn no_redirect_flag() { assert_eq!(auth(GOOD & !(1<<4)), AuthResult::RedirectFlagMissing); }
    #[test] fn no_callback_unobserved() { assert_eq!(auth(GOOD & !(1<<13)), AuthResult::Unobserved); }
    #[test] fn reauth_denied() { assert_eq!(auth(GOOD & !(1<<12)), AuthResult::GuardDenied); }
    #[test] fn lost_lease_denied() { assert_eq!(auth(GOOD & !(1<<11)), AuthResult::GuardDenied); }
    #[test] fn stale_epoch_denied() { assert_eq!(auth(GOOD & !(1<<9)), AuthResult::GuardDenied); }
    #[test] fn wrong_endpoint_denied() { assert_eq!(auth(GOOD & !(1<<10)), AuthResult::GuardDenied); }
    #[test] fn wrong_broker_denied() { assert_eq!(auth(GOOD & !(1<<7)), AuthResult::GuardDenied); }
    #[test] fn wrong_original_dest_denied() { assert_eq!(auth(GOOD & !(1<<8)), AuthResult::GuardDenied); }
    #[test] fn udp_denied() { assert_eq!(auth(GOOD & !(1<<6)), AuthResult::GuardDenied); }
    #[test] fn hidden_historical_owner_not_observed() {
        assert_eq!(auth(GOOD), auth(GOOD | (1<<14)));
    }
    #[test] fn hidden_sibling_direct_not_observed() {
        assert_eq!(auth(GOOD), auth(GOOD | (1<<15)));
    }
    #[test] fn absent_redirect_record_does_not_prove_clean() {
        assert_eq!(redirect(ISSUE), RedirectResult::UnqueriedStateCandidate);
        assert_eq!(redirect(ISSUE | 64), RedirectResult::UnqueriedStateCandidate);
    }
    #[test] fn records_present_and_not_clean() {
        assert_eq!(redirect(ISSUE | 1), RedirectResult::StateNotClear);
    }
    #[test] fn record_state_queried_clean() {
        assert_eq!(redirect(ISSUE | 3), RedirectResult::QueriedCleanCandidate);
    }
    #[test] fn no_redirect_callback_remains_unobserved() {
        assert_eq!(redirect(ISSUE & !128), RedirectResult::Unobserved);
    }
    #[test] fn record_missing_health_denies() {
        assert_eq!(redirect(ISSUE & !16), RedirectResult::HealthOrOwnerDenied);
    }
    #[test] fn no_unknown_equality_rule() {
        // The diagnostic never exposes an OriginProved/PacketBound result.
        assert!(matches!(auth(GOOD), AuthResult::ConditionalReceiptOnly));
    }
}
