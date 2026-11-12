//! R140 kernel classify action-rights guard, **pure** and no_std-compatible.
//! Does NOT provide a persistent OS kill switch. An unmodifiable CONTINUE
//! cannot lawfully be converted into BLOCK by a callout without action-write.
//! The caller supplies generated WDK constants; no magic numeric ACTION value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockDecision {
    Writable,
    VetoPriorPermit,
    MustPreserve,
}

#[inline]
pub const fn decision(rights:u32, prior_action:u32, action_write:u32, permit:u32)->BlockDecision {
    if action_write!=0 && rights & action_write != 0 {
        BlockDecision::Writable
    } else if prior_action == permit {
        BlockDecision::VetoPriorPermit
    } else {
        BlockDecision::MustPreserve
    }
}

/// Standalone reference of the same conditional writes as kernel guarded_block.
/// Unlike the kernel adapter this owns a local copy and performs no WFP API calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot { pub rights:u32, pub action:u32 }
#[inline]
pub fn try_block(s:&mut Snapshot,write:u32,permit:u32,block:u32)->bool {
    match decision(s.rights,s.action,write,permit) {
        BlockDecision::MustPreserve=>false,
        BlockDecision::Writable|BlockDecision::VetoPriorPermit=>{
            s.action=block;
            s.rights &= !write;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const W:u32=1; const P:u32=0x12;const B:u32=0x11;const C:u32=0x26;
    #[test] fn write_right_may_set_block_from_continue() {
        let mut v=Snapshot{rights:W,action:C};
        assert!(try_block(&mut v,W,P,B));assert_eq!(v,Snapshot{rights:0,action:B});
    }
    #[test] fn veto_only_a_prior_permit_without_write_right(){
        let mut v=Snapshot{rights:0,action:P};
        assert_eq!(decision(v.rights,v.action,W,P),BlockDecision::VetoPriorPermit);
        assert!(try_block(&mut v,W,P,B));assert_eq!(v.action,B);
    }
    #[test] fn unmodifiable_continue_is_preserved(){
        let mut v=Snapshot{rights:0,action:C};let original=v;
        assert!(!try_block(&mut v,W,P,B));assert_eq!(v,original);
    }
    #[test] fn unmodifiable_existing_block_is_preserved_not_rewritten(){
        let mut v=Snapshot{rights:0,action:B};let original=v;
        assert!(!try_block(&mut v,W,P,B));assert_eq!(v,original);
    }
    #[test] fn no_right_and_none_must_preserve(){
        for a in [0,3,7,0xffff_ffff]{let mut v=Snapshot{rights:0,action:a};let prev=v;
            assert!(!try_block(&mut v,W,P,B));assert_eq!(v,prev);}
    }
    #[test] fn do_not_discard_unrelated_right_bits(){
        let mut v=Snapshot{rights:0x101,action:P};assert!(try_block(&mut v,W,P,B));
        assert_eq!(v.rights,0x100);
        let mut v2=Snapshot{rights:0x100,action:C};assert!(!try_block(&mut v2,W,P,B));
        assert_eq!(v2.rights,0x100);
    }
    #[test] fn acquire_writable_block_no_right_is_left_untouched(){
        // FwpsAcquireWritableLayerDataPointer0 automatically sets BLOCK/clears right.
        let mut s=Snapshot{rights:0,action:B};let v=s;
        assert!(!try_block(&mut s,W,P,B));assert_eq!(s,v);
    }
    #[test] fn null_action_write_bit_is_not_permission(){
        let mut s=Snapshot{rights:u32::MAX,action:C};let before=s;
        assert!(!try_block(&mut s,0,P,B));assert_eq!(s,before);
    }
    #[test] fn cannot_write_permit_with_absent_write_permission(){
        assert_eq!(decision(0,C,W,P),BlockDecision::MustPreserve);
    }
    #[test] fn all_actions_need_permission_or_veto(){
        for rights in [0,1,2,3,256,257,u32::MAX]{
            for prior in [P,B,C,0,7,0x1234]{
                let mut s=Snapshot{rights,action:prior};let prev=s;
                let allowed=try_block(&mut s,W,P,B);
                assert_eq!(allowed,(rights&W!=0)||prior==P);
                if allowed {assert_eq!(s.action,B);assert_eq!(s.rights,rights&!W);}
                else {assert_eq!(s,prev);}
            }
        }
    }
}
