//! Source-owned broker worker accounting (no WFP/driver/test-signing access).
//! Only an authenticated receipt can reach the relay; invalid local ingress
//! is a per-socket refusal. Active capacity is reclaimed after join.
//! An error AFTER a receipt, or a worker panic, remains terminal to the service.

use std::{io,thread::{self,JoinHandle}};

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum WorkerOutcome {
    IngressRejected,
    Relayed,
}

pub struct WorkerPool {
    active:Vec<JoinHandle<io::Result<WorkerOutcome>>>,
    limit:usize,
    completed:usize,
    rejected:usize,
    dropped_capacity:usize,
}

impl WorkerPool {
    pub fn new(limit:usize)->Self {
        assert!(limit>0);
        Self{active:Vec::new(),limit,completed:0,rejected:0,dropped_capacity:0}
    }
    fn collect(&mut self,finished:thread::Result<io::Result<WorkerOutcome>>)->io::Result<()>{
        match finished{
            Ok(Ok(WorkerOutcome::IngressRejected))=>{
                self.rejected=self.rejected.saturating_add(1);Ok(())
            }
            Ok(Ok(WorkerOutcome::Relayed))=>{
                self.completed=self.completed.saturating_add(1);Ok(())
            }
            Ok(Err(_))|Err(_)=>Err(io::Error::other("authenticated_worker_failed")),
        }
    }
    /// Nonblocking reap: completion, including a panicked worker, is observed
    /// before accepting additional streams. Never hide an authenticated failure.
    pub fn poll(&mut self)->io::Result<()> {
        let mut failed=false;
        let mut i=0;
        while i<self.active.len(){
            if !self.active[i].is_finished(){i+=1;continue;}
            let handle=self.active.swap_remove(i);
            if self.collect(handle.join()).is_err(){failed=true;}
        }
        if failed{Err(io::Error::other("authenticated_worker_failed"))}else{Ok(())}
    }
    /// A saturated pool refuses the single accepted socket without a global
    /// kernel STOP. No new permit is generated and no direct fallback exists.
    pub fn spawn<F>(&mut self,worker:F)->io::Result<bool>
    where F:FnOnce()->io::Result<WorkerOutcome>+Send+'static {
        self.poll()?;
        if self.active.len()>=self.limit{
            self.dropped_capacity=self.dropped_capacity.saturating_add(1);
            return Ok(false);
        }
        self.active.push(thread::spawn(worker));
        Ok(true)
    }
    /// Join all remaining workers after sticky STOP, preserving fatal outcomes.
    pub fn finish(&mut self)->io::Result<()> {
        let mut failed=false;
        while let Some(worker)=self.active.pop(){
            if self.collect(worker.join()).is_err(){failed=true;}
        }
        if failed{Err(io::Error::other("authenticated_worker_failed"))}else{Ok(())}
    }
    pub fn active(&self)->usize{self.active.len()}
    pub fn completed(&self)->usize{self.completed}
    pub fn rejected_ingress(&self)->usize{self.rejected}
    pub fn dropped_capacity(&self)->usize{self.dropped_capacity}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::{Arc,Barrier,mpsc},time::{Duration,Instant}};

    #[test]
    fn local_ingress_rejection_does_not_terminate_live_relay(){
        let mut pool=WorkerPool::new(2);
        let (release,held)=mpsc::channel::<()>();
        assert!(pool.spawn(move||{
            held.recv().expect("controlled active relay");
            Ok(WorkerOutcome::Relayed)
        }).unwrap());
        assert!(pool.spawn(||Ok(WorkerOutcome::IngressRejected)).unwrap());
        // A rejected local socket is a normal per-flow failure, not a fatal
        // lease revocation; the already active connection must continue.
        let deadline=Instant::now()+Duration::from_secs(3);
        while pool.rejected_ingress()==0 && Instant::now()<deadline{
            pool.poll().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pool.rejected_ingress(),1);
        assert_eq!(pool.completed(),0);
        assert_eq!(pool.active(),1);
        release.send(()).unwrap();
        pool.finish().unwrap();
        assert_eq!(pool.completed(),1);
    }

    #[test]
    fn cap_counts_only_running_workers_and_reclaims_joins(){
        let mut pool=WorkerPool::new(2);
        let gate=Arc::new(Barrier::new(3));
        for _ in 0..2 {
            let gate=gate.clone();
            assert!(pool.spawn(move||{
                gate.wait();
                Ok(WorkerOutcome::Relayed)
            }).unwrap());
        }
        assert_eq!(pool.active(),2);
        assert!(!pool.spawn(||Ok(WorkerOutcome::Relayed)).unwrap());
        assert_eq!(pool.dropped_capacity(),1);
        // Release first two workers. A third admitted stream fits the exact
        // same capacity once their threads have really finished.
        gate.wait();
        let deadline=Instant::now()+Duration::from_secs(3);
        while pool.active()!=0 && Instant::now()<deadline{
            pool.poll().unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pool.active(),0);
        assert_eq!(pool.completed(),2);
        assert!(pool.spawn(||Ok(WorkerOutcome::Relayed)).unwrap());
        pool.finish().unwrap();
        assert_eq!(pool.completed(),3);
    }

    #[test]
    fn post_receipt_failure_is_not_misclassified_as_ingress_reject(){
        let mut pool=WorkerPool::new(2);
        assert!(pool.spawn(||Err(io::Error::other("claimed_ssh_failed"))).unwrap());
        assert!(pool.finish().is_err());
        assert_eq!(pool.rejected_ingress(),0);
        assert_eq!(pool.completed(),0);
    }

    #[test]
    fn worker_panic_is_fatal_and_not_silently_reaped(){
        let mut pool=WorkerPool::new(1);
        assert!(pool.spawn(||->io::Result<WorkerOutcome>{panic!("fixture panic")}).unwrap());
        assert!(pool.finish().is_err());
        assert_eq!(pool.completed(),0);
    }

    #[test]
    fn long_session_completion_count_is_not_a_lifetime_cap(){
        let mut pool=WorkerPool::new(32);
        for _ in 0..100 {
            assert!(pool.spawn(||Ok(WorkerOutcome::Relayed)).unwrap());
            pool.finish().unwrap();
        }
        assert_eq!(pool.completed(),100);
        assert_eq!(pool.dropped_capacity(),0);
    }
}
