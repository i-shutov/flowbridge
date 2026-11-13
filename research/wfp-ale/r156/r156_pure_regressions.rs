//! Standalone USER-MODE tests. This is NOT a driver or an implementation of WFP.
//! Only the three existing pure modules are included; never lib.rs/redirect.rs.
//! Synthetic integers are identities in a model, not live Windows object refs.
#![forbid(unsafe_code)]
#[allow(dead_code)]
#[path = "../kernel-r19/kernel/src/handoff.rs"]
mod handoff;
#[allow(dead_code)]
#[path = "../kernel-r19/kernel/src/ledger.rs"]
mod ledger;
#[allow(dead_code)]
#[path = "../kernel-r19/kernel/src/action_rights.rs"]
mod action_rights;

#[cfg(test)]
mod regression {
    use super::{action_rights as a, handoff as h, ledger as l};
    fn origin(endpoint: u64) -> h::Origin {
        h::Origin { pid: 7, epoch: 8, key: 9, endpoint, generation: 1 }
    }
    fn destination(family: u8) -> h::Destination {
        let mut ip = [0; 16];
        if family == 4 { ip[..4].copy_from_slice(&[192, 0, 2, 1]); }
        else { ip[..4].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]); ip[15] = 1; }
        h::Destination { family, port: 443, ip }
    }
    fn book() -> h::Book {
        let mut b = h::Book::new(); assert!(b.initialize([1; 16])); b
    }
    fn owner(pid: u64) -> l::Owner {
        let mut o = l::Owner::EMPTY;
        o.pid = pid; o.process = pid as usize; o.file = 10000 + pid as usize;
        o.epoch = 8; o.start_key = 9; o.live = true; o.name_len = 2; o.name[0] = b'a'; o
    }
    #[test]
    fn fresh_endpoint_33_only_hits_live_slot_cap() {
        let mut b = book();
        let mut first = None;
        for endpoint in 1..=h::CAP as u64 {
            let c = b.issue(origin(endpoint), destination(4), 1).unwrap();
            if endpoint == 1 { first = Some(c); }
        }
        assert!(b.issue(origin(33), destination(4), 2).is_none());
        assert!(!b.lost); // Distinguish slot capacity from endpoint replay.
        b.retire(first.unwrap());
        assert!(b.issue(origin(33), destination(4), 3).is_some());
        assert!(!b.lost);
    }
    #[test]
    fn tombstone_4097_is_a_terminal_session_limit() {
        let mut b = book();
        for endpoint in 1..=h::MAX_ENDPOINT_TOMBSTONES as u64 {
            let c = b.issue(origin(endpoint), destination(6), 1).unwrap(); b.retire(c);
        }
        assert!(!b.lost);
        assert!(b.issue(origin(4097), destination(6), 2).is_none());
        assert!(b.lost);
        assert!(!b.initialize([2; 16]));
    }
    #[test]
    fn retired_endpoint_poison_is_not_safe_reclamation() {
        let mut b = book(); let c = b.issue(origin(10), destination(4), 1).unwrap();
        b.retire(c);
        assert!(b.issue(origin(10), destination(4), 2).is_none());
        assert!(b.lost); assert!(!b.attest(origin(10), destination(4), 3));
    }
    #[test]
    fn zero_endpoint_does_not_mint_authority() {
        let mut b = book();
        assert!(b.issue(origin(0), destination(4), 1).is_none());
        assert!(!b.lost); assert!(b.issue(origin(1), destination(4), 2).is_some());
    }
    #[test]
    fn auth_cannot_move_to_another_process_epoch() {
        for family in [4, 6] {
            let mut b = book(); b.issue(origin(10), destination(family), 1).unwrap();
            let mut reused = origin(10); reused.epoch += 1;
            assert!(!b.attest(reused, destination(family), 2));
            assert!(b.attest(origin(10), destination(family), 2));
        }
    }
    #[test]
    fn same_target_different_endpoint_still_needs_separate_auth() {
        let mut b = book(); let d = destination(4);
        let first = b.issue(origin(10), d, 1).unwrap();
        let second = b.issue(origin(11), d, 1).unwrap();
        assert!(b.attest(origin(10), d, 2));
        assert!(b.take(second, 3).is_none());
        assert!(b.take(first, 3).is_some());
        assert!(!b.attest(origin(11), d, 4));
    }
    #[test]
    fn two_roles_survive_churn_until_ledger_cap_not_forever() {
        let mut ledger = l::Ledger::new(); ledger.session = 1;
        ledger.born(owner(1)).unwrap(); // synthetic selected role
        ledger.born(owner(2)).unwrap(); // synthetic broker role
        for pid in 3..=l::MAX_OWNERS as u64 {
            ledger.born(owner(pid)).unwrap(); ledger.died(pid, pid as usize);
        }
        assert!(ledger.lookup(1).is_some()); assert!(ledger.lookup(2).is_some());
        assert_eq!(ledger.born(owner(257)), Err(l::Denied::Full));
        assert!(ledger.lookup(1).is_none()); assert!(ledger.lookup(2).is_none());
    }
    #[test]
    fn unrelated_pid_reuse_latches_ledger_loss() {
        let mut ledger = l::Ledger::new();
        ledger.born(owner(1)).unwrap(); ledger.born(owner(2)).unwrap(); ledger.died(2, 2);
        let mut reused = owner(2); reused.process = 3; reused.epoch += 1;
        assert_eq!(ledger.born(reused), Err(l::Denied::ReusedPid));
        assert!(ledger.lookup(1).is_none());
    }
    #[test]
    fn book_claim_is_not_a_live_process_proof() {
        let mut ledger = l::Ledger::new(); ledger.born(owner(7)).unwrap();
        let mut b = book(); let c = b.issue(origin(10), destination(4), 1).unwrap();
        assert!(b.attest(origin(10), destination(4), 2)); ledger.died(7, 7);
        assert!(b.take(c, 3).is_some()); // Book alone does not observe death.
        assert!(ledger.lookup(7).is_none()); // R19 CLAIM separately requires lookup.
    }
    // Test-only source composition, NOT the kernel adapter or a new callout.
    // Symbols deliberately synthetic: generated WDK constants are not compiled here.
    fn composed_self(rights: u32, prior: u32) -> (a::Snapshot, bool) {
        const W: u32 = 1; const P: u32 = 12; const B: u32 = 11; const C: u32 = 26;
        let mut s = a::Snapshot { rights, action: prior };
        if s.rights & W != 0 { s.action = C; }
        if s.rights & W == 0 { a::try_block(&mut s, W, P, B); return (s, false); }
        (s, true)
    }
    #[test]
    fn writable_self_returns_continue_from_outer_wrapper() {
        for rights in [1, 257, u32::MAX] {
            for prior in [0, 11, 12, 26] {
                let (s, query) = composed_self(rights, prior);
                assert!(query); assert_eq!(s.action, 26); assert_eq!(s.rights, rights);
            }
        }
    }
    #[test]
    fn readonly_self_branch_is_unreachable() {
        for rights in [0, 256, u32::MAX - 1] {
            for prior in [0, 11, 12, 26] {
                let (s, query) = composed_self(rights, prior);
                assert!(!query); assert_eq!(s.action, if prior == 12 { 11 } else { prior });
                assert_eq!(s.rights, rights);
            }
        }
    }
    #[test]
    fn independent_losses_revoke_different_model_objects() {
        let mut ledger = l::Ledger::new(); ledger.born(owner(7)).unwrap();
        let mut b = book(); let c = b.issue(origin(10), destination(4), 1).unwrap();
        b.kill(); assert!(!b.attest(origin(10), destination(4), 2));
        assert!(b.take(c, 3).is_none()); assert!(ledger.lookup(7).is_some());
        // No assertion of real SSH/BFE enforcement follows from a local Book kill.
    }
}
