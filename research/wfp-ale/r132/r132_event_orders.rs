//! R132: event-order campaign using unchanged R19 pure modules.
//! The composition below is TEST-ONLY, not redirect.rs, not an OS callback adapter.
//! Process/file/endpoint integers are synthetic. Revocation/death events mean APPLIED.
//! No Win32/WFP, sockets, drivers, filters, SSH, dependency, or runtime installation.
#![forbid(unsafe_code)]
#![allow(dead_code)]
#[path = "../kernel-r19/kernel/src/ledger.rs"] mod ledger;
#[path = "../kernel-r19/kernel/src/handoff.rs"] mod handoff;
#[path = "../kernel-r19/kernel/src/auth_appid.rs"] mod auth_appid;
#[path = "../kernel-r19/policy_plan.rs"] mod policy_plan;
use handoff::{Book, Context, Destination, Origin, TTL};
use ledger::{Ledger, Owner};
use std::io::{self, Write};

// Event indices: 0=AUTH, 1=second AUTH, 2=primary CLAIM, 3=valid retry CLAIM,
// 4=applied hazard, 5=advance clock beyond TTL. Issue is fixed before the trace.
// Hazards: 0=none, 1=selected process exit observed, 2=PID rebirth observed,
// 3=STOP applied, 4=endpoint reuse attempted (same identity/destination).
// Primary CLAIM: 0=valid, 1=payload changed, 2=foreign session,
// 3=unknown sequence, 4=UDP protocol byte (not a real UDP socket).
const SELECTED: &[u8] = &[b's',0];
const PROXY: &[u8] = &[b'b',0];
fn owner(pid: u64, name: &[u8]) -> Owner {
    let mut o=Owner::EMPTY; o.pid=pid; o.process=1000+pid as usize;
    o.file=2000+pid as usize; o.epoch=101; o.start_key=102; o.live=true;
    o.name_len=name.len(); o.name[..name.len()].copy_from_slice(name); o
}
fn destination(family: u8) -> Destination {
    let mut ip=[0;16];
    if family==4 {ip[..4].copy_from_slice(&[192,0,2,1]);}
    else {ip[..4].copy_from_slice(&[0x20,0x01,0x0d,0xb8]);ip[15]=1;}
    Destination{family,port:443,ip}
}
struct Machine { ledger: Ledger, book: Book, token: Context, origin: Origin,
    selected: Owner, dest: Destination, now: u64 }
impl Machine {
    fn new(family:u8)->Self {
        let mut l=Ledger::new(); l.session=77; let o=owner(7,SELECTED);
        l.born(o).unwrap();l.born(owner(9,PROXY)).unwrap();
        let (_,generation)=l.lookup(7).unwrap();
        let origin=Origin{pid:7,epoch:o.epoch,key:o.start_key,endpoint:21,generation};
        let mut b=Book::new();assert!(b.initialize([17;16]));
        let dest=destination(family);let token=b.issue(origin,dest,1).unwrap();
        Self{ledger:l,book:b,token,origin,selected:o,dest,now:2}
    }
    // Only a test composition of readiness; a current synthetic broker lease is
    // assumed. No heartbeat timing, BFE/filter presence or physical SSH is inferred.
    fn ready(&mut self)->bool {
        if self.book.lost || self.ledger.lookup(9).is_none() {self.book.kill();false}
        else {true}
    }
    fn auth(&mut self)->bool {
        if !self.ready() {return false;}
        let Some((o,generation))=self.ledger.lookup(7) else{return false;};
        if !auth_appid::original_matches_selected(&o.name[..o.name_len],PROXY,SELECTED) {return false;}
        self.book.attest(Origin{pid:o.pid,epoch:o.epoch,key:o.start_key,
            endpoint:21,generation},self.dest,self.now)
    }
    fn claim(&mut self,c:Context)->bool {
        if !self.ready() {return false;}
        // Match the source ordering in redirect.rs CLAIM: terminal Book::take
        // FIRST, then live Ledger lookup and identity/name comparison.
        let Some(receipt)=self.book.take(c,self.now) else{return false;};
        let Some((o,generation))=self.ledger.lookup(receipt.number(32)) else{return false;};
        receipt.matches_origin(Origin{pid:o.pid,epoch:o.epoch,key:o.start_key,
            endpoint:receipt.number(56),generation}) && &o.name[..o.name_len]==SELECTED
    }
    fn primary(&self,variant:u8)->Context {
        let mut c=self.token;
        match variant {
            0=>{}, 1=>c.0[80]^=1, 2=>c.0[8]^=1,
            3=>c.0[24..32].copy_from_slice(&999u64.to_le_bytes()),
            4=>c.0[73]=17, _=>panic!("variant")
        } c
    }
    fn apply(&mut self,event:u8,hazard:u8,variant:u8)->bool {
        match event {
            0|1=>self.auth(),
            2=>self.claim(self.primary(variant)),
            3=>self.claim(self.token),
            4=>match hazard {
                0=>false,
                1=>{self.ledger.died(7,self.selected.process);true},
                2=>{self.ledger.died(7,self.selected.process);let mut n=self.selected;
                    n.process+=100;n.file+=100;n.epoch+=100;n.start_key+=100;
                    self.ledger.born(n).is_ok()},
                3=>{self.book.kill();true},
                4=>self.book.issue(self.origin,self.dest,self.now).is_some(),
                _=>panic!("hazard")
            },
            5=>{self.now=TTL+2;true},
            _=>panic!("event")
        }
    }
}
fn permutations()->Vec<[u8;6]> {
    fn walk(prefix:&mut Vec<u8>, used:u8, out:&mut Vec<[u8;6]>) {
        if prefix.len()==6 {let mut a=[0;6];a.copy_from_slice(prefix);out.push(a);return;}
        for n in 0..6 {if used&(1<<n)==0 {prefix.push(n);walk(prefix,used|(1<<n),out);prefix.pop();}}
    }
    let mut out=Vec::new();walk(&mut Vec::new(),0,&mut out);out
}
#[derive(Debug,PartialEq,Eq)]
struct Trace { result:[bool;6], book_lost:[bool;6], ledger_lost:[bool;6], live:[bool;6] }
fn trace(family:u8,hazard:u8,variant:u8,order:[u8;6])->Trace {
    let mut m=Machine::new(family);
    let mut t=Trace{result:[false;6],book_lost:[false;6],ledger_lost:[false;6],live:[false;6]};
    let(mut claims,mut auths)=(0,0);
    let(mut hazard_applied,mut expired)=(false,false);
    for (i,&event) in order.iter().enumerate() {
        let ok=m.apply(event,hazard,variant);
        if event<=1 && ok {auths+=1;}
        if (event==2||event==3)&&ok {
            claims+=1;
            assert!(!expired && !(hazard_applied&&hazard!=0),"admission after applied invalidation");
        }
        if event==4 {hazard_applied=true;}
        if event==5 {expired=true;}
        t.result[i]=ok;t.book_lost[i]=m.book.lost;t.ledger_lost[i]=m.ledger.lost;
        t.live[i]=m.ledger.lookup(7).is_some();
    }
    assert!(claims<=1 && auths<=1,"one-shot invariant");t
}
fn bits(values:[bool;6])->String {values.iter().map(|v|if *v {'1'}else{'0'}).collect()}
fn campaign(out:&mut impl Write)->io::Result<usize> {
    let orders=permutations();let mut count=0;
    for family in [4,6] {for hazard in 0..5 {for variant in 0..5 {for &order in &orders {
        let t=trace(family,hazard,variant,order);
        let ord:String=order.iter().map(|n|(b'0'+n)as char).collect();
        writeln!(out,"{family}|{hazard}|{variant}|{ord}|{}|{}|{}|{}",
            bits(t.result),bits(t.book_lost),bits(t.ledger_lost),bits(t.live))?;
        count+=1;
    }}}} Ok(count)
}
fn main() {
    let args:Vec<_>=std::env::args().skip(1).collect();
    if args!=["--campaign"] {eprintln!("usage: r132_event_orders --campaign");std::process::exit(2);}
    // Explicit stack only for this disposable test process, not a system setting.
    let job=std::thread::Builder::new().name("r132-campaign".into())
        .stack_size(8*1024*1024).spawn(|| {
            let out=io::stdout();let mut buf=io::BufWriter::new(out.lock());
            campaign(&mut buf).and_then(|n|{buf.flush()?;Ok(n)})
        });
    let code=match job {Ok(j)=>match j.join() {
        Ok(Ok(36000))=>0,Ok(Ok(_))=>3,
        Ok(Err(e))=>{eprintln!("campaign output: {e}");2},Err(_)=>3
    },Err(e)=>{eprintln!("campaign thread: {e}");2}};
    if code!=0 {std::process::exit(code);}

}
#[cfg(test)]
mod schedule_tests {
    use super::*;
    use std::sync::{Arc,Mutex,Barrier,mpsc};
    use std::time::Duration;
    #[test] fn valid_auth_then_claim_once(){let mut m=Machine::new(4);assert!(m.auth());assert!(m.claim(m.token));assert!(!m.claim(m.token));}
    #[test] fn early_claim_is_terminal(){let mut m=Machine::new(6);assert!(!m.claim(m.token));assert!(!m.auth());}
    #[test] fn foreign_session_does_not_consume(){let mut m=Machine::new(4);assert!(m.auth());assert!(!m.claim(m.primary(2)));assert!(m.claim(m.token));}
    #[test] fn unknown_sequence_does_not_consume(){let mut m=Machine::new(6);assert!(m.auth());assert!(!m.claim(m.primary(3)));assert!(m.claim(m.token));}
    #[test] fn changed_payload_consumes(){let mut m=Machine::new(4);assert!(m.auth());assert!(!m.claim(m.primary(1)));assert!(!m.claim(m.token));}
    #[test] fn udp_byte_consumes_not_a_udp_network_test(){let mut m=Machine::new(6);assert!(m.auth());assert!(!m.claim(m.primary(4)));assert!(!m.claim(m.token));}
    #[test] fn observed_death_before_claim_denies(){let mut m=Machine::new(4);assert!(m.auth());m.apply(4,1,0);assert!(!m.claim(m.token));}
    #[test] fn acceptance_before_death_is_not_retroactive_revocation(){let mut m=Machine::new(6);assert!(m.auth());assert!(m.claim(m.token));m.apply(4,1,0);assert!(!m.claim(m.token));}
    #[test] fn pid_rebirth_latches_global_loss(){let mut m=Machine::new(4);assert!(m.auth());assert!(!m.apply(4,2,0));assert!(m.ledger.lost);assert!(!m.claim(m.token));assert!(m.book.lost);}
    #[test] fn stop_applied_blocks_future_claim(){let mut m=Machine::new(6);assert!(m.auth());m.apply(4,3,0);assert!(!m.claim(m.token));}
    #[test] fn endpoint_reuse_poisoning_is_preserved(){let mut m=Machine::new(4);assert!(!m.apply(4,4,0));assert!(m.book.lost);assert!(!m.auth());}
    #[test] fn ttl_advance_prevents_auth_and_claim(){let mut m=Machine::new(6);assert!(m.auth());m.apply(5,0,0);assert!(!m.claim(m.token));assert!(!m.auth());}
    #[test] fn permutation_set_is_exact(){let p=permutations();assert_eq!(p.len(),720);let s:std::collections::BTreeSet<_>=p.into_iter().collect();assert_eq!(s.len(),720);}
    #[test] fn weak_liveness_gate_has_counterexample(){let mut m=Machine::new(4);assert!(m.auth());m.apply(4,1,0);assert!(m.book.take(m.token,m.now).is_some());let mut strict=Machine::new(4);assert!(strict.auth());strict.apply(4,1,0);assert!(!strict.claim(strict.token));}
    #[test] fn real_threads_two_claimants_only_one_accepts(){
        for family in [4,6] {for _ in 0..16 {
            let mut m=Machine::new(family);assert!(m.auth());let shared=Arc::new(Mutex::new(m));let barrier=Arc::new(Barrier::new(3));
            let joins:Vec<_>=(0..2).map(|_|{let s=shared.clone();let b=barrier.clone();std::thread::spawn(move||{b.wait();let mut m=s.lock().unwrap();let c=m.token;m.claim(c)})}).collect();
            barrier.wait();let n=joins.into_iter().map(|j|usize::from(j.join().unwrap())).sum::<usize>();assert_eq!(n,1);
        }}
    }
    fn ordered_invalidation(hazard:u8, first:bool)->bool {
        let mut m=Machine::new(6);assert!(m.auth());let s=Arc::new(Mutex::new(m));
        let(tx,rx)=mpsc::sync_channel(1);let a=s.clone();let b=s.clone();
        let invalidator=std::thread::spawn(move||{if !first {rx.recv_timeout(Duration::from_secs(10)).unwrap();}let mut m=a.lock().unwrap();m.apply(4,hazard,0);});
        // Invalidate-first is joined before allowing the competing CLAIM. In the
        // reverse order the channel establishes a precise happens-before edge.
        if first {invalidator.join().unwrap();let mut m=b.lock().unwrap();let c=m.token;m.claim(c)}
        else {let claimant=std::thread::spawn(move||{let ok={let mut m=b.lock().unwrap();let c=m.token;m.claim(c)};tx.send(()).unwrap();ok});let ok=claimant.join().unwrap();invalidator.join().unwrap();ok}
    }
    #[test] fn threads_observed_death_before_claim(){assert!(!ordered_invalidation(1,true));}
    #[test] fn threads_claim_before_observed_death(){assert!(ordered_invalidation(1,false));}
    #[test] fn threads_stop_before_claim(){assert!(!ordered_invalidation(3,true));}
}
