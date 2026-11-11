//! Source-anchored, pure user-mode negative tests: imports the *exact* R19 Ledger.
//! No WFP, driver, filter, socket, runner or network functionality.
#[path = "../kernel-r19/kernel/src/ledger.rs"]
mod ledger;

#[cfg(test)]
mod tests {
    use super::ledger::{Denied, Ledger, Owner, MAX_OWNERS};
    fn owner(pid: u64) -> Owner {
        let mut o=Owner::EMPTY;
        o.pid=pid; o.process=pid as usize + 0x1000;
        o.file=pid as usize + 0x2000;
        o.epoch=17; o.start_key=pid+100; o.live=true;
        o.name_len=2; o.name[..2].copy_from_slice(&[b'x',0]); o
    }
    fn session() -> Ledger { let mut l=Ledger::new(); l.session=77; l }

    #[test]
    fn target_257th_denied_despite_dead_historical_processes() {
        let mut l=session();
        for pid in 1..=MAX_OWNERS as u64 {
            l.born(owner(pid)).unwrap();
            l.died(pid,pid as usize+0x1000);
        }
        assert_eq!(l.born(owner(900_000)),Err(Denied::Full));
        assert!(l.lost);
        for family in [4,6] {
            assert_eq!(l.observe(900_000,family as u64+5,family,&[b'x',0]),Err(Denied::Lost));
        }
    }
    #[test]
    fn unrelated_257th_birth_invalidates_live_selected_owner() {
        let mut l=session();
        l.born(owner(900_000)).unwrap();
        for pid in 1..MAX_OWNERS as u64 {l.born(owner(pid)).unwrap();}
        assert_eq!(l.observe(900_000,70,4,&[b'x',0]),Ok(()));
        assert_eq!(l.born(owner(999_999)),Err(Denied::Full));
        assert_eq!(l.observe(900_000,71,6,&[b'x',0]),Err(Denied::Lost));
    }
    #[test]
    fn reused_pid_latches_loss_without_capacity_exhaustion() {
        let mut l=session();
        l.born(owner(8)).unwrap(); l.died(8,0x1008);
        let mut next=owner(8);next.process+=100;next.epoch+=1;
        assert_eq!(l.born(next),Err(Denied::ReusedPid));
        assert!(l.lost);
    }
}
