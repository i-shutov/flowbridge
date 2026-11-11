//! R121 source-contract-only, clean-room user-mode model; no socket/WFP/driver.
//! The narrow scope guard is a policy hypothesis, not a provenance attestation.
#![forbid(unsafe_code)]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct Request {
    family: u8,
    address: &'static str,
    port: u16,
    compartment: u32,
    pid_epoch: u64,
    endpoint: u64,
    ssh_healthy: bool,
    tcp: bool,
}
fn r19_remote_target(r: Request) -> Option<(u8, &'static str, u16)> {
    if !r.tcp || !r.ssh_healthy { return None; }
    // This is only the eventual SSH direct-tcpip selector, NOT the 128-byte
    // WFP redirect context (which carries other source identity fields).
    Some((r.family, r.address, r.port))
}
fn single_compartment_guard(r: Request, approved: u32)
    -> Option<(u8, &'static str, u16)> {
    if r.compartment != approved { return None; }
    r19_remote_target(r)
}
#[cfg(test)] mod tests {
    use super::*;
    fn sample(family: u8) -> Request {
        Request {family, address: if family == 4 {"10.55.0.7"} else {"fd00:dead::7"},
            port: 443, compartment: 7, pid_epoch: 100, endpoint: 11,
            ssh_healthy: true, tcp: true}
    }
    #[test] fn different_windows_compartments_same_ssh_selector() {
        for fam in [4,6] { let a=sample(fam);
            let b=Request {compartment:99,..a};
            assert_eq!(r19_remote_target(a), r19_remote_target(b)); }
    }
    #[test] fn distinct_process_epoch_and_endpoint_do_not_restore_namespace() {
        let a=sample(4);
        let b=Request {compartment:99,pid_epoch:101,endpoint:12,..a};
        assert_eq!(r19_remote_target(a), r19_remote_target(b));
    }
    #[test] fn explicit_scope_guard_denies_other_compartments() {
        for fam in [4,6] { let a=sample(fam);
            assert!(single_compartment_guard(a,7).is_some());
            assert!(single_compartment_guard(Request{compartment:99,..a},7).is_none()); }
    }
    #[test] fn failure_does_not_prove_system_no_direct() {
        for fam in [4,6] {let a=sample(fam);
            assert!(r19_remote_target(Request{ssh_healthy:false,..a}).is_none());
            assert!(r19_remote_target(Request{tcp:false,..a}).is_none()); }
    }
}
