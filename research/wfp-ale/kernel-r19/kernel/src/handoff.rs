//! Fixed wire layout shared by the actual kernel redirect and user-mode broker.
//! A parsed context is DATA, not authority. Only the private kernel ticket book
//! plus a same-requestor claim can authorize this experimental handoff.
pub const LEN: usize = 128;
pub const ARM_LEN: usize = 528;
pub const ARM: u32 = 0x22e404;
pub const CLAIM: u32 = 0x22e408;
pub const PING: u32 = 0x22e40c;
pub const STOP: u32 = 0x22e410;
pub const LEASE: u64 = 30_000_000; // 3 seconds, Windows interrupt-time 100ns units
pub const TTL: u64 = 100_000_000; // 10 seconds to consume one context
pub const CAP: usize = 32;
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Destination { pub family: u8, pub port: u16, pub ip: [u8; 16] }
impl Destination {
    pub fn valid(&self) -> bool {
        if self.port == 0 { return false; }
        match self.family {
            4 => self.ip[4..].iter().all(|&b| b == 0)
                && self.ip[..4] != [0; 4] && self.ip[0] < 224,
            6 => self.ip != [0; 16] && self.ip[0] != 0xff
                && !(self.ip[0] == 0xfe && self.ip[1] & 0xc0 == 0x80)
                && !(self.ip[..10] == [0; 10] && self.ip[10..12] == [0xff, 0xff]),
            _ => false,
        }
    }
}
#[derive(Clone, Copy)]
pub struct Origin { pub pid:u64, pub epoch:u64, pub key:u64, pub endpoint:u64, pub generation:u64 }
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Context(pub [u8; LEN]);
impl Context {
    pub const EMPTY: Self = Self([0; LEN]);
    fn put(&mut self, at:usize, value:u64) { self.0[at..at+8].copy_from_slice(&value.to_le_bytes()); }
    pub fn number(&self, at:usize) -> u64 {
        let mut a=[0;8]; a.copy_from_slice(&self.0[at..at+8]); u64::from_le_bytes(a)
    }
    pub fn parse(bytes:&[u8]) -> Option<Self> {
        if bytes.len()!=LEN {return None;}
        let mut c=Self::EMPTY; c.0.copy_from_slice(bytes);
        if &c.0[..4]!=b"FBR3" || c.0[4..8]!=[1,0,128,0]
            || c.0[8..24]==[0;16] || c.0[73]!=6 || c.0[76..80]!=[0;4]
            || c.0[104..].iter().any(|&x|x!=0)
            || [24,32,40,48,56,64,96].iter().any(|&at|c.number(at)==0)
            || !c.destination().valid() {return None;}
        Some(c)
    }
    pub fn destination(&self)->Destination {
        let mut ip=[0;16];ip.copy_from_slice(&self.0[80..96]);
        Destination{family:self.0[72],port:u16::from_be_bytes([self.0[74],self.0[75]]),ip}
    }
    pub fn matches_origin(&self, o:Origin)->bool {
        self.number(32)==o.pid && self.number(40)==o.epoch && self.number(48)==o.key
            && self.number(56)==o.endpoint && self.number(64)==o.generation
    }
}
#[derive(Clone, Copy)]
struct Slot { context:Context, live:bool, auth_seen:bool }
impl Slot { const EMPTY:Self=Self{context:Context::EMPTY,live:false,auth_seen:false}; }
pub struct Book { session:[u8;16], slots:[Slot;CAP], sequence:u64, pub lost:bool }
impl Book {
    pub const fn new()->Self {Self{session:[0;16],slots:[Slot::EMPTY;CAP],sequence:0,lost:false}}
    pub fn initialize(&mut self, session:[u8;16])->bool {
        if self.session!=[0;16] || session==[0;16] {self.lost=true;return false;}
        self.session=session;true
    }
    pub fn issue(&mut self, origin:Origin, destination:Destination, now:u64)->Option<Context> {
        if self.lost || self.session==[0;16] || now==0 || !destination.valid()
            || [origin.pid,origin.epoch,origin.key,origin.endpoint,origin.generation].contains(&0) {return None;}
        // Expired records are retired, never reissued with the same sequence.
        for s in &mut self.slots {if s.live && now.saturating_sub(s.context.number(96))>TTL{s.live=false;}}
        // A live endpoint may have only one active redirect ticket; never
        // guess which origin a second AUTH indication belongs to.
        if self.slots.iter().any(|s| s.live && s.context.number(56)==origin.endpoint){self.lost=true;return None;}
        let index=self.slots.iter().position(|s|!s.live)?;
        self.sequence=match self.sequence.checked_add(1){Some(n)=>n,None=>{self.lost=true;return None;}};
        let mut c=Context::EMPTY;c.0[..8].copy_from_slice(b"FBR3\x01\x00\x80\x00");
        c.0[8..24].copy_from_slice(&self.session);
        for (at,n) in [(24,self.sequence),(32,origin.pid),(40,origin.epoch),(48,origin.key),
                       (56,origin.endpoint),(64,origin.generation),(96,now)]{c.put(at,n);}
        c.0[72]=destination.family;c.0[73]=6;c.0[74..76].copy_from_slice(&destination.port.to_be_bytes());
        c.0[80..96].copy_from_slice(&destination.ip);
        self.slots[index]=Slot{context:c,live:true,auth_seen:false};Some(c)
    }
    /// Authorization must come from the *same native ALE_AUTH_CONNECT* classify,
    /// not from a user-mode TCP table or an arbitrary supplied receipt.
    pub fn attest(&mut self, origin:Origin, destination:Destination, now:u64)->bool {
        if self.lost || now==0 || !destination.valid(){return false;}
        let mut found=None;
        for (idx,slot) in self.slots.iter().enumerate(){
            if slot.live && slot.context.matches_origin(origin) && slot.context.destination()==destination {
                if found.is_some(){self.lost=true;return false;}
                found=Some(idx);
            }
        }
        let Some(idx)=found else{return false;};
        let slot=&mut self.slots[idx];
        let when=slot.context.number(96);
        if slot.auth_seen || now<when || now-when>TTL{return false;}
        slot.auth_seen=true;
        true
    }
    pub fn retire(&mut self, context:Context) {for s in &mut self.slots{if s.live && s.context==context{s.live=false;}}}
    pub fn take(&mut self, context:Context, now:u64)->Option<Context> {
        if self.lost || context.0[8..24]!=self.session {return None;}
        let s=self.slots.iter_mut().find(|s|s.live && s.context.number(24)==context.number(24))?;
        s.live=false; // terminal even on failed, unauthenticated or replayed claim
        if !s.auth_seen || s.context!=context || now<context.number(96) || now-context.number(96)>TTL{return None;}
        Some(context)
    }
    pub fn kill(&mut self) {self.lost=true;for s in &mut self.slots{s.live=false;}}
}
#[cfg(test)]
mod tests {
    use super::*;
    fn o()->Origin{Origin{pid:7,epoch:8,key:9,endpoint:10,generation:1}}
    fn d()->Destination{let mut ip=[0;16];ip[..4].copy_from_slice(&[192,0,2,1]);Destination{family:4,port:443,ip}}
    fn book()->Book{let mut b=Book::new();assert!(b.initialize([1;16]));b}
    #[test]fn wire_roundtrip_both_families(){let mut b=book();for f in [4,6]{let mut dest=d();dest.family=f;if f==6{dest.ip=[0;16];dest.ip[15]=1;}
        let c=b.issue(o(),dest,1).unwrap();assert!(Context::parse(&c.0).is_some());assert!(c.destination()==dest);assert!(c.matches_origin(o()));}}
    #[test]fn claim_is_single_use(){let mut b=book();let c=b.issue(o(),d(),1).unwrap();assert!(b.attest(o(),d(),2));assert!(b.take(c,2).is_some());assert!(b.take(c,2).is_none());}
    #[test]fn repaired_failed_claim_not_accepted(){let mut b=book();let c=b.issue(o(),d(),1).unwrap();let mut wrong=c;wrong.0[80]^=1;assert!(b.attest(o(),d(),2));
        assert!(b.take(wrong,2).is_none());assert!(b.take(c,2).is_none());}
    #[test]fn old_context_does_not_survive_slot_reuse(){let mut b=book();let c=b.issue(o(),d(),1).unwrap();b.retire(c);let n=b.issue(o(),d(),2).unwrap();
        assert!(c!=n);assert!(b.attest(o(),d(),3));assert!(b.take(c,3).is_none());assert!(b.take(n,3).is_some());}
    #[test]fn foreign_session_does_not_consume(){let mut b=book();let c=b.issue(o(),d(),1).unwrap();let mut x=c;x.0[8]^=1;
        assert!(b.attest(o(),d(),2));assert!(b.take(x,2).is_none());assert!(b.take(c,2).is_some());}
    #[test]fn expired_and_clock_reversed_denied(){for t in [0,TTL+2]{let mut b=book();let c=b.issue(o(),d(),1).unwrap();let _=b.attest(o(),d(),2);assert!(b.take(c,t).is_none());}}
    #[test]fn queue_bound_and_loss_never_promote(){let mut b=book();for _ in 0..CAP{assert!(b.issue(o(),d(),1).is_some());}assert!(b.issue(o(),d(),1).is_none());b.kill();assert!(b.issue(o(),d(),1).is_none());}
    #[test]fn malformed_protocol_scope_reserved_length(){let c=book().issue(o(),d(),1).unwrap();for at in [0,4,6,73,76,104]{let mut x=c;x.0[at]^=1;assert!(Context::parse(&x.0).is_none());}assert!(Context::parse(&c.0[..127]).is_none());}
    #[test]fn no_zero_identity(){let mut b=book();let mut x=o();x.epoch=0;assert!(b.issue(x,d(),1).is_none());x=o();x.key=0;assert!(b.issue(x,d(),1).is_none());}
    #[test]fn no_auth_receipt_claim_fails_closed(){let mut b=book();let c=b.issue(o(),d(),1).unwrap();assert!(b.take(c,2).is_none());assert!(!b.attest(o(),d(),3));}
    #[test]fn foreign_origin_endpoint_cannot_attest(){let mut b=book();let c=b.issue(o(),d(),1).unwrap();let mut other=o();other.endpoint=11;
      assert!(!b.attest(other,d(),2));other=o();other.epoch=999;assert!(!b.attest(other,d(),2));
      let mut other_dst=d();other_dst.port=444;assert!(!b.attest(o(),other_dst,2));assert!(b.attest(o(),d(),2));assert!(b.take(c,2).is_some());}
    #[test]fn duplicated_endpoint_latches_loss(){let mut b=book();b.issue(o(),d(),1).unwrap();assert!(b.issue(o(),d(),2).is_none());assert!(b.lost);}
    #[test]fn auth_replay_denied(){let mut b=book();b.issue(o(),d(),1).unwrap();assert!(b.attest(o(),d(),2));assert!(!b.attest(o(),d(),3));}
    #[test]fn no_scope_multicast_unspecified_or_mapped(){let mut dest=d();dest.ip=[0;16];assert!(!dest.valid());dest.ip[0]=224;assert!(!dest.valid());dest.family=6;dest.ip[0]=0xff;assert!(!dest.valid());dest.ip=[0;16];dest.ip[0]=0xfe;dest.ip[1]=0x80;assert!(!dest.valid());}
}
