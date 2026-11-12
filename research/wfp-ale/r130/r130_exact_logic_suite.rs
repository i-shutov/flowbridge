//! R130: test the exact existing R19 pure modules, never the kernel adapter.
//! Integer process/file/endpoint fields below are SYNTHETIC, not OS references.
//! No Windows API, socket, driver, filter, service, SSH or external crate.
#![forbid(unsafe_code)]
#![allow(dead_code)]

#[path = "../kernel-r19/kernel/src/ledger.rs"]
mod ledger;
#[path = "../kernel-r19/kernel/src/handoff.rs"]
mod handoff;
#[path = "../kernel-r19/kernel/src/auth_appid.rs"]
mod auth_appid;
#[path = "../kernel-r19/policy_plan.rs"]
mod policy_plan;

#[cfg(test)]
mod integration {
    use super::{auth_appid, handoff::{Book, Context, Destination, Origin, TTL}, ledger::{Denied, Ledger, Owner}, policy_plan::Plan};

    fn image() -> Vec<u8> {
        r"\device\harddiskvolume1\selected\app.exe".encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
    fn owner(pid: u64) -> Owner {
        let name = image();
        let mut o = Owner::EMPTY;
        o.pid = pid; o.process = 1000 + pid as usize; o.file = 2000 + pid as usize;
        o.epoch = 101; o.start_key = 102; o.live = true; o.name_len = name.len();
        o.name[..name.len()].copy_from_slice(&name); o
    }
    fn setup() -> (Ledger, Book, Owner) {
        let o = owner(7); let mut l = Ledger::new(); l.session = 77;
        l.born(o).unwrap(); let mut b = Book::new(); assert!(b.initialize([17;16])); (l,b,o)
    }
    fn destination(family: u8) -> Destination {
        let mut ip = [0;16];
        match family {
            4 => ip[..4].copy_from_slice(&[192,0,2,1]),
            6 => { ip[..4].copy_from_slice(&[0x20,0x01,0x0d,0xb8]); ip[15] = 1; }
            _ => panic!("test family"),
        }
        Destination { family, port:443, ip }
    }
    fn origin(l: &Ledger, o: Owner, endpoint: u64) -> Origin {
        let (found,generation) = l.lookup(o.pid).expect("synthetic live owner");
        Origin { pid:found.pid,epoch:found.epoch,key:found.start_key,endpoint,generation }
    }
    // Test-only composition, NOT production CLAIM and NOT an atomic OS liveness check.
    fn live_candidate_take(l: &Ledger, b: &mut Book, c: Context, now: u64) -> bool {
        let Some((o,generation)) = l.lookup(c.number(32)) else { return false; };
        let observed = Origin { pid:o.pid,epoch:o.epoch,key:o.start_key,
            endpoint:c.number(56),generation };
        c.matches_origin(observed) && b.take(c,now).is_some()
    }

    #[test]
    fn exact_ledger_to_book_roundtrip_both_families() {
        for family in [4,6] {
            let (mut l,mut b,o) = setup(); let d=destination(family);
            l.observe(o.pid,21,family as u32,&image()).unwrap();
            let w=l.pop().unwrap().unwrap();
            assert_eq!(w.pid,o.pid); assert_eq!(w.protocol,6);
            let i=Origin{pid:w.pid,epoch:w.epoch,key:w.start_key,endpoint:w.endpoint,generation:w.owner_generation};
            let c=b.issue(i,d,1).unwrap(); assert!(Context::parse(&c.0).is_some());
            assert!(b.attest(i,d,2)); assert!(live_candidate_take(&l,&mut b,c,3));
            assert!(!live_candidate_take(&l,&mut b,c,4));
        }
    }
    #[test]
    fn death_between_observation_and_dequeue_rejects_witness() {
        let (mut l,_,o)=setup(); l.observe(o.pid,21,4,&image()).unwrap();
        l.died(o.pid,o.process); assert!(matches!(l.pop(),Err(Denied::Dead)));
    }
    #[test]
    fn every_origin_dimension_is_checked_at_attest() {
        for family in [4,6] { for field in 0..5 {
            let (l,mut b,o)=setup(); let i=origin(&l,o,21); let d=destination(family);
            let c=b.issue(i,d,1).unwrap(); let mut bad=i;
            match field {0=>bad.pid+=1,1=>bad.epoch+=1,2=>bad.key+=1,3=>bad.endpoint+=1,_=>bad.generation+=1}
            assert!(!b.attest(bad,d,2)); assert!(b.attest(i,d,2));
            assert!(live_candidate_take(&l,&mut b,c,3));
        }}
    }
    #[test]
    fn book_alone_is_not_a_process_liveness_proof() {
        let (mut l,mut b,o)=setup(); let i=origin(&l,o,21); let d=destination(4);
        let c=b.issue(i,d,1).unwrap(); assert!(b.attest(i,d,2)); l.died(o.pid,o.process);
        assert!(!live_candidate_take(&l,&mut b,c,3));
        // Expected boundary, NOT a new defect: Book does not subscribe to process death.
        assert!(b.take(c,3).is_some());
    }
    #[test]
    fn pid_reuse_does_not_upgrade_old_receipt() {
        let (mut l,mut b,o)=setup(); let i=origin(&l,o,21); let d=destination(4);
        let c=b.issue(i,d,1).unwrap(); assert!(b.attest(i,d,2)); l.died(o.pid,o.process);
        let mut new=o; new.process+=100; new.file+=100; new.epoch+=100; new.start_key+=100;
        assert_eq!(l.born(new),Err(Denied::ReusedPid)); assert!(l.lost);
        assert!(!live_candidate_take(&l,&mut b,c,3));
    }
    #[test]
    fn endpoint_tombstone_is_not_cleared_by_claim() {
        for f in [4,6] {
            let (l,mut b,o)=setup();let i=origin(&l,o,21);let d=destination(f);
            let c=b.issue(i,d,1).unwrap();assert!(b.attest(i,d,2));assert!(b.take(c,3).is_some());
            assert!(b.issue(i,d,4).is_none());assert!(b.lost);
        }
    }
    #[test]
    fn same_destination_new_endpoint_gets_distinct_ticket() {
        for f in [4,6] {
            let (l,mut b,o)=setup();let i=origin(&l,o,21);let d=destination(f);
            let c=b.issue(i,d,1).unwrap();b.retire(c);
            let mut j=i;j.endpoint=22;let next=b.issue(j,d,2).unwrap();
            assert_ne!(c.number(24),next.number(24));assert!(!b.attest(i,d,3));
            assert!(b.attest(j,d,3));assert!(b.take(next,4).is_some());
        }
    }
    #[test]
    fn same_basename_other_full_path_is_not_selected() {
        let (mut l,_,o)=setup();
        let sibling:Vec<u8>=r"\device\harddiskvolume1\sibling\app.exe".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(!auth_appid::original_matches_selected(&sibling,&sibling,&image()));
        assert_eq!(l.observe(o.pid,21,4,&sibling),Err(Denied::PathMismatch));
    }
    #[test]
    fn bfe_appid_terminator_is_not_kernel_name_data() {
        let kernel=image();let mut bfe=kernel.clone();bfe.extend_from_slice(&[0,0]);
        let p=Plan::new(&bfe,[1091,1092]).unwrap();assert_eq!(p.appid,bfe);
        assert!(!auth_appid::original_matches_selected(&bfe,&bfe,&bfe));
        assert!(auth_appid::original_matches_selected(&kernel,&kernel,&kernel));
    }
    #[test]
    fn proxy_current_appid_is_not_original_process_authority() {
        let kernel=image();let proxy=[b'p',0];
        assert!(auth_appid::original_matches_selected(&kernel,&proxy,&kernel));
        assert!(!auth_appid::original_matches_selected(&proxy,&kernel,&kernel));
        let l=Ledger::new();assert!(l.lookup(7).is_none()); // AppId match does not create owner.
    }
    #[test]
    fn early_claim_cannot_be_repaired_by_later_auth() {
        let (l,mut b,o)=setup();let i=origin(&l,o,21);let d=destination(4);
        let c=b.issue(i,d,1).unwrap();assert!(b.take(c,2).is_none());
        assert!(!b.attest(i,d,3));assert!(b.take(c,4).is_none());
    }
    #[test]
    fn changed_payload_consumes_matching_sequence_without_replay() {
        let (l,mut b,o)=setup();let i=origin(&l,o,21);let d=destination(6);
        let c=b.issue(i,d,1).unwrap();assert!(b.attest(i,d,2));
        let mut bad=c;bad.0[95]^=1;assert!(b.take(bad,3).is_none());assert!(b.take(c,4).is_none());
    }
    #[test]
    fn ttl_boundary_is_inclusive_but_not_one_tick_later() {
        for delta in [TTL,TTL+1] {
            let (l,mut b,o)=setup();let i=origin(&l,o,21);let d=destination(4);
            let c=b.issue(i,d,1).unwrap();assert!(b.attest(i,d,2));
            assert_eq!(b.take(c,1+delta).is_some(),delta==TTL);
        }
    }
    #[test]
    fn udp_receipt_rejected_and_kill_never_rearms_book() {
        let (l,mut b,o)=setup();let i=origin(&l,o,21);let d=destination(6);
        let c=b.issue(i,d,1).unwrap();let mut udp=c;udp.0[73]=17;
        assert!(Context::parse(&udp.0).is_none());assert!(b.attest(i,d,2));b.kill();
        assert!(b.take(c,3).is_none());let mut fresh=i;fresh.endpoint=22;
        assert!(b.issue(fresh,d,4).is_none());assert!(!b.initialize([18;16]));
    }
}
