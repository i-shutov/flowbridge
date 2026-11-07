//! Fixed, non-evicting kernel ledger. Same source is compiled into the .sys and unit tests.
//! OS pointers never leave the ledger. Successful entries own references until unload.
//! This supplies candidate same-classify observations, NOT redirect/PacketBound admission.
pub const MAX_OWNERS: usize = 256;
pub const MAX_RECORDS: usize = 32;
pub const MAX_NAME: usize = 512;
pub const WIRE_MAGIC: u32 = 0x39314746; // FG19
#[derive(Clone, Copy)]
pub struct Owner {
    pub pid: u64,
    pub process: usize,
    pub file: usize,
    pub epoch: u64,
    pub start_key: u64,
    pub live: bool,
    pub name_len: usize,
    pub name: [u8; MAX_NAME],
}
impl Owner {
    pub const EMPTY: Self = Self { pid:0, process:0, file:0, epoch:0, start_key:0, live:false, name_len:0, name:[0;MAX_NAME] };
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Witness {
    pub magic: u32,
    pub size: u32,
    pub session: u64,
    pub receipt: u64,
    pub endpoint: u64,
    pub pid: u64,
    pub epoch: u64,
    pub start_key: u64,
    pub owner_generation: u64,
    pub family: u32,
    pub flags: u32,
    pub appid_len: u32,
    pub protocol: u32,
    pub appid: [u8; MAX_NAME],
}
impl Witness {
    pub const EMPTY: Self = Self { magic:WIRE_MAGIC, size:core::mem::size_of::<Self>() as u32,
        session:0, receipt:0, endpoint:0, pid:0, epoch:0, start_key:0, owner_generation:0,
        family:0, flags:0, appid_len:0, protocol:0, appid:[0;MAX_NAME] };
}
#[derive(Debug, PartialEq, Eq)]
pub enum Denied { Invalid, Unknown, Dead, ReusedPid, Full, Lost, PathMismatch }
pub struct Ledger {
    pub owners: [Owner; MAX_OWNERS],
    used: usize,
    queue: [Witness; MAX_RECORDS],
    read: usize,
    count: usize,
    receipt: u64,
    pub lost: bool,
    pub session: u64,
}
impl Ledger {
    pub const fn new() -> Self { Self { owners:[Owner::EMPTY;MAX_OWNERS], used:0,
        queue:[Witness::EMPTY;MAX_RECORDS], read:0, count:0, receipt:0, lost:false, session:0 } }
    pub fn born(&mut self, owner: Owner) -> Result<(), Denied> {
        if self.lost { return Err(Denied::Lost); }
        if owner.pid==0 || owner.process==0 || owner.file==0 || owner.epoch==0 || owner.start_key==0
            || !owner.live || owner.name_len==0 || owner.name_len>MAX_NAME || owner.name_len%2!=0 {
            return Err(Denied::Invalid);
        }
        if let Some(existing) = self.owners[..self.used].iter_mut().find(|o|o.pid==owner.pid) {
            existing.live=false; self.lost=true; return Err(Denied::ReusedPid);
        }
        if self.used==MAX_OWNERS { self.lost=true; return Err(Denied::Full); }
        self.owners[self.used]=owner; self.used+=1; Ok(())
    }
    pub fn died(&mut self, pid:u64, process:usize) {
        if let Some(owner)=self.owners[..self.used].iter_mut().find(|o|o.pid==pid) {
            if owner.process!=process { self.lost=true; }
            owner.live=false;
        }
        // Existing/pre-driver processes are outside this observer's authority.
    }
    pub fn observe(&mut self,pid:u64,endpoint:u64,family:u32,appid:&[u8])->Result<(),Denied> {
        if self.lost {return Err(Denied::Lost);}
        if self.session==0 || endpoint==0 || (family!=4&&family!=6) || appid.is_empty()
            || appid.len()>MAX_NAME || appid.len()%2!=0 {return Err(Denied::Invalid);}
        let slot=self.owners[..self.used].iter().position(|o|o.pid==pid).ok_or(Denied::Unknown)?;
        let owner=&self.owners[slot];
        if !owner.live {return Err(Denied::Dead);}
        if appid != &owner.name[..owner.name_len] {return Err(Denied::PathMismatch);}
        if self.count==MAX_RECORDS || self.receipt==u64::MAX {self.lost=true;return Err(Denied::Full);}
        self.receipt+=1;
        let mut w=Witness::EMPTY;
        w.session=self.session;w.receipt=self.receipt;w.endpoint=endpoint;
        w.pid=owner.pid;w.epoch=owner.epoch;w.start_key=owner.start_key;
        w.owner_generation=(slot+1) as u64;w.family=family;
        // Flags: birth-observed, referenced process/file, exact path match. NO admission bit.
        w.flags=0x0f;w.protocol=6;w.appid_len=appid.len() as u32;w.appid[..appid.len()].copy_from_slice(appid);
        self.queue[(self.read+self.count)%MAX_RECORDS]=w;self.count+=1;Ok(())
    }
    pub fn pop(&mut self)->Result<Option<Witness>,Denied> {
        if self.lost {return Err(Denied::Lost);}
        if self.count==0 {return Ok(None);}
        let w=self.queue[self.read];self.queue[self.read]=Witness::EMPTY;
        self.read=(self.read+1)%MAX_RECORDS;self.count-=1;
        let slot=(w.owner_generation-1) as usize;
        if slot>=self.used || !self.owners[slot].live {return Err(Denied::Dead);}
        Ok(Some(w))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn owner(pid:u64)->Owner { let mut o=Owner::EMPTY;o.pid=pid;o.process=pid as usize;
        o.file=10000+pid as usize;o.epoch=5;o.start_key=6;o.live=true;o.name_len=2;o.name[0]=97;o }
    fn ledger()->Ledger{let mut l=Ledger::new();l.session=123;l}
    #[test]fn positive_both_families(){for f in [4,6]{let mut l=ledger();l.born(owner(1)).unwrap();l.observe(1,9,f,&[97,0]).unwrap();let w=l.pop().unwrap().unwrap();assert_eq!(w.epoch,5);assert_eq!(w.start_key,6);assert_eq!(w.flags,15);assert_eq!(w.family,f);}}
    #[test]fn preexisting_unknown_not_upgraded(){assert_eq!(ledger().observe(1,9,4,&[97,0]),Err(Denied::Unknown));}
    #[test]fn pid_reuse_latches_forever(){let mut l=ledger();l.born(owner(1)).unwrap();l.died(1,1);let mut o=owner(1);o.epoch=77;o.process=99;assert_eq!(l.born(o),Err(Denied::ReusedPid));assert_eq!(l.observe(1,9,4,&[97,0]),Err(Denied::Lost));}
    #[test]fn exit_before_and_after_classify_rejected(){let mut l=ledger();l.born(owner(1)).unwrap();l.observe(1,9,4,&[97,0]).unwrap();l.died(1,1);assert!(matches!(l.pop(),Err(Denied::Dead)));assert_eq!(l.observe(1,10,4,&[97,0]),Err(Denied::Dead));}
    #[test]fn wrong_exit_object_poisoned(){let mut l=ledger();l.born(owner(1)).unwrap();l.died(1,99);assert!(l.lost);}
    #[test]fn sibling_exact_path_not_basename(){let mut l=ledger();l.born(owner(1)).unwrap();assert_eq!(l.observe(1,9,4,&[98,0]),Err(Denied::PathMismatch));}
    #[test]fn queue_overflow_no_overwrite(){let mut l=ledger();l.born(owner(1)).unwrap();for i in 0..MAX_RECORDS{l.observe(1,1+i as u64,4,&[97,0]).unwrap();}assert_eq!(l.observe(1,99,4,&[97,0]),Err(Denied::Full));assert!(matches!(l.pop(),Err(Denied::Lost)));}
    #[test]fn owner_cap_no_eviction(){let mut l=ledger();for p in 1..=MAX_OWNERS{l.born(owner(p as u64)).unwrap();}assert_eq!(l.born(owner(999)),Err(Denied::Full));}
    #[test]fn no_epoch_or_file_object_no_owner(){for field in 0..4{let mut l=ledger();let mut o=owner(1);match field{0=>o.epoch=0,1=>o.file=0,2=>o.start_key=0,_=>o.process=0};assert_eq!(l.born(o),Err(Denied::Invalid));}}
    #[test]fn invalid_endpoint_and_family_denied(){let mut l=ledger();l.born(owner(1)).unwrap();assert_eq!(l.observe(1,0,4,&[97,0]),Err(Denied::Invalid));assert_eq!(l.observe(1,9,7,&[97,0]),Err(Denied::Invalid));}
    #[test]fn repeated_receipt_dequeue_does_not_replay(){let mut l=ledger();l.born(owner(1)).unwrap();l.observe(1,9,4,&[97,0]).unwrap();assert!(l.pop().unwrap().is_some());assert!(l.pop().unwrap().is_none());}
}
