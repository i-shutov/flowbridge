//! R103: conservative, read-only BFE same-sublayer arbitration candidate inventory.
//! Strictly management-plane observation; never certifies callback, identity or no-DIRECT.
//! Clean-room Rust + documented Microsoft fwpuclnt ABI. No driver, network or policy writes.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(windows, target_pointer_width = "64")))]
fn main() {
    eprintln!("unavailable: requires authorized Windows x86_64 user-mode host");
    std::process::exit(2);
}

#[cfg(all(windows, target_pointer_width = "64"))]
mod win {
    use std::{ffi::c_void, ptr, slice};

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Guid { d1: u32, d2: u16, d3: u16, d4: [u8;8] }
    impl Guid {
        const fn from_u128(n:u128)->Self {
            Self { d1:(n>>96) as u32,d2:(n>>80) as u16,d3:(n>>64) as u16,
                d4:[(n>>56) as u8,(n>>48) as u8,(n>>40) as u8,(n>>32) as u8,
                    (n>>24) as u8,(n>>16) as u8,(n>>8) as u8,n as u8] }
        }
    }
    #[repr(C)] struct DisplayData { name:*mut u16, desc:*mut u16 }
    #[repr(C)] struct Blob { len:u32, data:*mut u8 }
    // x64 FWP_VALUE0 / FWP_CONDITION_VALUE0: four-byte enum + padding + 8-byte union.
    // FWP_UINT64 uses a pointer in the union. Never treat it as an inline integer.
    #[repr(C)] struct Value { kind:u32, _pad:u32, bits:u64 }
    #[repr(C)] struct Condition { key:Guid, op:u32, val:Value }
    #[repr(C)] struct Action { kind:u32, key:Guid }
    #[repr(C)] struct Filter {
        key:Guid, display:DisplayData, flags:u32, provider:*mut Guid,
        provider_data:Blob, layer:Guid, sublayer:Guid, weight:Value,
        num_conditions:u32, conditions:*mut Condition, action:Action,
        // FWPM_FILTER0 anonymous union is 16 bytes, eight-byte aligned.
        context:[u64;2], reserved:*mut Guid, filter_id:u64,
        effective_weight:Value,
    }
    const SUB:Guid=Guid::from_u128(0x1649f024_25b3_4e01_9ca1_5ca803010019);
    const BASE:u128=0x1649f030_25b3_4e01_9ca1_5ca803010019;
    const LAYERS:[Guid;4]=[
        Guid::from_u128(0xc38d57d1_05a7_4c33_904f_7fbceee60e82), // AUTH v4
        Guid::from_u128(0x4a72393b_319f_44bc_84c3_ba54dcb3b6b4), // AUTH v6
        Guid::from_u128(0xc6e63c8c_b784_4562_aa7d_0a67cfcaf9a3), // REDIRECT v4
        Guid::from_u128(0x587e54a7_8046_42ba_a0aa_b716250fc7fd), // REDIRECT v6
    ];
    const LABELS:[&str;4]=["auth_connect_v4","auth_connect_v6",
                            "connect_redirect_v4","connect_redirect_v6"];
    const FWP_EMPTY:u32=0;
    const FWP_UINT64:u32=4;
    // Values from the Microsoft fwpmtypes.h filter flags contract.
    // BFE may add INDEXED on read; DISABLED means the filter is NOT effective.
    const FWPM_FILTER_FLAG_DISABLED:u32=0x00000020;
    const FWPM_FILTER_FLAG_INDEXED:u32=0x00000040;
    // R19 installs the owned filters with flags=0. INDEXED is an allowed
    // BFE-derived observation; all other unexpected owned flags are UNKNOWN.
    fn owned_flags_expected(flags:u32)->bool {
        flags & !FWPM_FILTER_FLAG_INDEXED == 0
    }
    fn foreign_filter_disabled(flags:u32)->bool {
        flags & FWPM_FILTER_FLAG_DISABLED != 0
    }
    const PAGE:u32=128;
    const MAX_VISIBLE:u64=131072;
    const RPC_C_AUTHN_WINNT:u32=10;

    #[link(name="fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineOpen0(server:*const u16,authn:u32,id:*const c_void,
                          session:*const c_void,handle:*mut *mut c_void)->u32;
        fn FwpmEngineClose0(handle:*mut c_void)->u32;
        fn FwpmFilterCreateEnumHandle0(handle:*mut c_void,template:*const c_void,
                                       enumerator:*mut *mut c_void)->u32;
        fn FwpmFilterEnum0(handle:*mut c_void,enumerator:*mut c_void,requested:u32,
                           entries:*mut *mut *mut Filter,returned:*mut u32)->u32;
        fn FwpmFilterDestroyEnumHandle0(handle:*mut c_void,enumerator:*mut c_void)->u32;
        fn FwpmFreeMemory0(raw:*mut *mut c_void);
    }
    struct Engine(*mut c_void);
    impl Drop for Engine {
        fn drop(&mut self) {if !self.0.is_null(){unsafe{let _=FwpmEngineClose0(self.0);}}}
    }
    struct EnumHandle { engine:*mut c_void,enumerator:*mut c_void }
    impl EnumHandle {
        fn destroy(mut self)->Result<(),(&'static str,u32)> {
            let rc=unsafe{FwpmFilterDestroyEnumHandle0(self.engine,self.enumerator)};
            self.enumerator=ptr::null_mut();
            if rc!=0 {return Err(("destroy_enumerator",rc));}
            Ok(())
        }
    }
    impl Drop for EnumHandle {
        fn drop(&mut self){if !self.enumerator.is_null(){
            unsafe{let _=FwpmFilterDestroyEnumHandle0(self.engine,self.enumerator);}
        }}
    }
    // Per Microsoft, ONLY the returned pointer array is freed, not its elements.
    struct PageBuffer(*mut *mut Filter);
    impl Drop for PageBuffer {
        fn drop(&mut self){if !self.0.is_null(){unsafe{
            let mut raw=self.0.cast::<c_void>();FwpmFreeMemory0(&mut raw);
        }}}
    }
    fn effective(f:&Filter)->Option<u64> {
        if f.effective_weight.kind!=FWP_UINT64 {return None;}
        let p=f.effective_weight.bits as usize as *const u64;
        if p.is_null(){return None;}
        Some(unsafe{p.read_unaligned()})
    }
    #[derive(Default)]
    struct Counts { greater:[u64;4],equal:[u64;4],lower:[u64;4],
                    disabled_visible:[u64;4],visible:u64 }
    fn inventory()->Result<Counts,(&'static str,u32)> {
        let mut raw: *mut c_void=ptr::null_mut();
        let rc=unsafe{FwpmEngineOpen0(ptr::null(),RPC_C_AUTHN_WINNT,
                                      ptr::null(),ptr::null(),&mut raw)};
        if rc!=0||raw.is_null(){return Err(("open",if rc==0{1}else{rc}));}
        let engine=Engine(raw);
        // One enumerator is a single ACL-limited BFE filter snapshot, per
        // FwpmFilterEnum0. An explicit read transaction around the entire
        // enumeration (up to 1,024 pages) would hold a BFE transaction lock.
        // Resolve the four owned baselines FROM THE SAME ENUMERATOR as the
        // foreign filters, not by an earlier GetByKey0 snapshot.
        let mut owned_weights:[Option<u64>;4]=[None;4];
        let mut foreign_weights:[Vec<u64>;4]=std::array::from_fn(|_|Vec::new());
        // NULL template: enumerate all *visible* filters, including other providers.
        let mut eh:*mut c_void=ptr::null_mut();
        let rc=unsafe{FwpmFilterCreateEnumHandle0(engine.0,ptr::null(),&mut eh)};
        if rc!=0||eh.is_null(){return Err(("create_enumerator",if rc==0{1}else{rc}));}
        let enumerator=EnumHandle{engine:engine.0,enumerator:eh};
        let mut counts=Counts::default();
        loop {
            let mut entries:*mut *mut Filter=ptr::null_mut();
            let mut returned=0u32;
            let rc=unsafe{FwpmFilterEnum0(engine.0,enumerator.enumerator,PAGE,
                                         &mut entries,&mut returned)};
            let page=PageBuffer(entries);
            if rc!=0 {return Err(("enum_page",rc));}
            if returned>PAGE||(returned>0&&page.0.is_null()) {
                return Err(("enum_page_shape",1));
            }
            if counts.visible+(returned as u64)>MAX_VISIBLE {
                return Err(("enum_budget_exceeded",1));
            }
            if returned>0 {
                for &fp in unsafe{slice::from_raw_parts(page.0,returned as usize)} {
                    if fp.is_null(){return Err(("null_filter_entry",1));}
                    let f=unsafe{&*fp};
                    counts.visible+=1;
                    for i in 0..4 {
                        let key=Guid::from_u128(BASE+((i as u128)<<96));
                        if f.key==key {
                            if owned_weights[i].is_some() {return Err(("duplicate_baseline",1));}
                            if f.layer!=LAYERS[i]||f.sublayer!=SUB||f.weight.kind!=FWP_EMPTY {
                                return Err(("baseline_shape",1));
                            }
                            // A disabled (or unexpectedly reflagged) owned filter cannot
                            // serve as a meaningful reference for live arbitration.
                            if !owned_flags_expected(f.flags) {
                                return Err(("baseline_flags_unverified",f.flags));
                            }
                            owned_weights[i]=Some(effective(f).ok_or(("baseline_effective_weight",1))?);
                        } else if f.layer==LAYERS[i] && f.sublayer==SUB {
                            // BFE may return a disabled competitor with an old effective
                            // weight. It is visible, but NOT a current arbitrator.
                            if foreign_filter_disabled(f.flags) {
                                counts.disabled_visible[i]+=1;
                            } else {
                                foreign_weights[i].push(effective(f).ok_or(("foreign_effective_weight",1))?);
                            }
                        }
                    }
                }
            }
            if returned<PAGE {break;}
        }
        enumerator.destroy()?;
        for i in 0..4 {
            // ACL-denied/missing owned baseline is UNKNOWN, never zero risk.
            let baseline=owned_weights[i].ok_or(("baseline_not_visible",1))?;
            for foreign in &foreign_weights[i] {
                if *foreign>baseline {counts.greater[i]+=1;}
                else if *foreign==baseline {counts.equal[i]+=1;}
                else {counts.lower[i]+=1;}
            }
        }
        Ok(counts)
    }
    pub fn run()->i32 {
        match inventory(){
            Err((stage,code))=>{
                println!("{{\"status\":\"UNKNOWN\",\"stage\":\"{stage}\",\"code\":{code},\"kernel_proof\":false,\"no_direct_proof\":false}}");
                2
            }
            Ok(c)=>{
                let mut candidate=false;
                for i in 0..4 {
                    candidate|=c.greater[i]>0||c.equal[i]>0;
                    println!("{{\"rule\":\"{}\",\"visible_higher\":{},\"visible_equal\":{},\"visible_lower\":{},\"visible_disabled\":{},\"match_and_runtime_action_unverified\":true}}",
                             LABELS[i],c.greater[i],c.equal[i],c.lower[i],c.disabled_visible[i]);
                }
                // Absence of a visible candidate is still UNKNOWN: enum is ACL-filtered.
                println!("{{\"status\":\"{}\",\"visible_filters\":{},\"single_enum_snapshot\":true,\"acl_hidden_filters_possible\":true,\"kernel_proof\":false,\"no_direct_proof\":false}}",
                         if candidate{"VISIBLE_ARBITRATION_CANDIDATE"}else{"UNKNOWN_NO_VISIBLE_CANDIDATE"},c.visible);
                if candidate {3} else {4}
            }
        }
    }
    #[cfg(test)] mod tests {
        use super::*;
        #[test] fn abi_prefix_and_trailing_weight(){
            assert_eq!(std::mem::size_of::<Guid>(),16);
            assert_eq!(std::mem::size_of::<Value>(),16);
            assert_eq!(std::mem::size_of::<Action>(),20);
            assert_eq!(std::mem::offset_of!(Filter,action),128);
            assert_eq!(std::mem::offset_of!(Filter,filter_id),176);
            assert_eq!(std::mem::offset_of!(Filter,effective_weight),184);
            assert_eq!(std::mem::size_of::<Filter>(),200);
        }
        #[test] fn disabled_and_unknown_owned_flags_fail_closed(){
            assert!(owned_flags_expected(0));
            assert!(owned_flags_expected(FWPM_FILTER_FLAG_INDEXED));
            assert!(!owned_flags_expected(FWPM_FILTER_FLAG_DISABLED));
            assert!(!owned_flags_expected(FWPM_FILTER_FLAG_DISABLED|FWPM_FILTER_FLAG_INDEXED));
            assert!(!owned_flags_expected(0x10)); // PERMIT_IF_CALLOUT_UNREGISTERED
            assert!(foreign_filter_disabled(FWPM_FILTER_FLAG_DISABLED));
            assert!(foreign_filter_disabled(FWPM_FILTER_FLAG_DISABLED|FWPM_FILTER_FLAG_INDEXED));
            assert!(!foreign_filter_disabled(FWPM_FILTER_FLAG_INDEXED));
        }
        #[test] fn exact_rule_order(){
            for i in 0..4 {assert_eq!(Guid::from_u128(BASE+((i as u128)<<96)).d1,0x1649f030+i as u32);}
        }
    }
}
#[cfg(all(windows, target_pointer_width="64"))]
fn main(){std::process::exit(win::run());}
