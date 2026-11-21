//! R220: independent USER-MODE/no-driver truth-table model for R19 AUTH_CONNECT.
//! Distinguishes FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED (0x00100000)
//! from FWP_CONDITION_FLAG_IS_PROXY_CONNECTION (0x00200000).
//! A successful SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS is NOT evidence that
//! the *new* physical SSH socket has IS_CONNECTION_REDIRECTED set.
//! Every observation is synthetic; no real Windows classify is claimed.
#![forbid(unsafe_code)]

const REAUTHORIZE: u32 = 0x0000_0004;
const CONNECTION_REDIRECTED: u32 = 0x0010_0000;
const PROXY_CONNECTION: u32 = 0x0020_0000;
const HONORING_POLICY_AUTHORIZE: u32 = 0x0200_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision { NotScoped, PermitCandidate, Block }

#[derive(Clone, Copy)]
struct Observation {
    original_selected: bool, // BFE FWPM_CONDITION_ALE_ORIGINAL_APP_ID
    tcp: bool,               // BFE FWPM_CONDITION_IP_PROTOCOL == TCP
    current_app_valid: bool, // R19 auth_appid predicate; not a second identity
    flags: u32,              // WFP FWPS_FIELD_ALE_AUTH_CONNECT_*_FLAGS
    broker_loopback: bool,   // exact family-appropriate address and broker port
    redirected_metadata: bool, // required original dest and target PID present
    origin_verified: bool,     // kernel PID + epoch + endpoint + ticket
}

fn r19_auth_candidate(o: Observation) -> Decision {
    if !o.original_selected || !o.tcp { return Decision::NotScoped; }
    if o.flags & CONNECTION_REDIRECTED == 0
        || o.flags & (REAUTHORIZE | HONORING_POLICY_AUTHORIZE) != 0
        || !o.current_app_valid || !o.broker_loopback
        || !o.redirected_metadata || !o.origin_verified {
        return Decision::Block;
    }
    // The flag PROXY_CONNECTION is *not* tested by R19's auth_check.
    // Even this outcome is NOT proof of a final WFP PERMIT.
    Decision::PermitCandidate
}

fn original_leg() -> Observation {
    Observation { original_selected:true,tcp:true,current_app_valid:true,
        flags:CONNECTION_REDIRECTED,broker_loopback:true,
        redirected_metadata:true,origin_verified:true }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn original_redirected_leg_is_only_a_candidate() {
        assert_eq!(r19_auth_candidate(original_leg()),Decision::PermitCandidate);
    }
    #[test] fn proxy_records_do_not_imply_redirected_flag() {
        let mut o=original_leg();o.flags=PROXY_CONNECTION;
        assert_eq!(r19_auth_candidate(o),Decision::Block);
        o.flags=0;
        assert_eq!(r19_auth_candidate(o),Decision::Block);
    }
    #[test] fn both_flags_are_not_automatically_an_authority() {
        let mut o=original_leg();o.flags|=PROXY_CONNECTION;
        assert_eq!(r19_auth_candidate(o),Decision::PermitCandidate);
        o.origin_verified=false;
        assert_eq!(r19_auth_candidate(o),Decision::Block);
    }
    #[test] fn physical_ssh_remote_is_rejected_even_with_both_flags() {
        let mut o=original_leg();o.flags|=PROXY_CONNECTION;o.broker_loopback=false;
        assert_eq!(r19_auth_candidate(o),Decision::Block);
        o.flags=PROXY_CONNECTION;
        assert_eq!(r19_auth_candidate(o),Decision::Block);
    }
    #[test] fn reauthorize_and_honoring_are_distinct_negatives() {
        for flag in [REAUTHORIZE,HONORING_POLICY_AUTHORIZE] {
            let mut o=original_leg();o.flags|=flag;
            assert_eq!(r19_auth_candidate(o),Decision::Block);
        }
    }
    #[test] fn incomplete_metadata_and_malformed_current_never_permit() {
        let mut o=original_leg();o.redirected_metadata=false;
        assert_eq!(r19_auth_candidate(o),Decision::Block);
        o=original_leg();o.current_app_valid=false;
        assert_eq!(r19_auth_candidate(o),Decision::Block);
    }
    #[test] fn unrelated_original_and_udp_are_out_of_scope() {
        let mut o=original_leg();o.original_selected=false;
        assert_eq!(r19_auth_candidate(o),Decision::NotScoped);
        o=original_leg();o.tcp=false;
        assert_eq!(r19_auth_candidate(o),Decision::NotScoped);
    }
}
