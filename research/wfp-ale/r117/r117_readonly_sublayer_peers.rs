//! R117: read-only, ACL-limited snapshot of visible BFE sublayer weights.
//! An observed weight peer is NOT a matching filter, runtime arbitration,
//! kernel-origin process evidence, packet capture or a no-DIRECT proof.
#![deny(unsafe_op_in_unsafe_fn)]
const OWNER_KEY: u128 = 0x1649f024_25b3_4e01_9ca1_5ca803010019;
const OWNER_WEIGHT: u16 = 0x7000;
const PAGE: u32 = 64;
const CAP: u64 = 16384;

#[derive(Default, Clone, Copy)]
struct Count { total:u64, owners:u64, higher:u64, equal:u64, lower:u64, descriptor_ok:bool }
fn classify(c:Count)->i32 {
    if c.total>CAP || c.owners!=1 || !c.descriptor_ok
        || c.higher.checked_add(c.equal).and_then(|x|x.checked_add(c.lower))
            != c.total.checked_sub(1) {return 2;}
    if c.higher>0 || c.equal>0 {3} else {4}
}

#[cfg(not(all(windows,target_pointer_width="64")))]
fn main(){eprintln!("UNAVAILABLE: authorized Windows x64 required; no BFE calls");std::process::exit(2)}

#[cfg(all(windows,target_pointer_width="64"))]
mod native {
    use super::*;
    use std::{ffi::c_void,ptr,slice};
    #[repr(C)] #[derive(Clone,Copy,PartialEq,Eq)]
    struct Guid {d1:u32,d2:u16,d3:u16,d4:[u8;8]}
    impl Guid {
        const fn from_u128(n:u128)->Self {
            Self{d1:(n>>96)as u32,d2:(n>>80)as u16,d3:(n>>64)as u16,
                d4:[(n>>56)as u8,(n>>48)as u8,(n>>40)as u8,(n>>32)as u8,
                    (n>>24)as u8,(n>>16)as u8,(n>>8)as u8,n as u8]}
        }
    }
    #[repr(C)] struct Display {name:*mut u16,description:*mut u16}
    #[repr(C)] struct Blob {size:u32,data:*mut u8}
    #[repr(C)] struct SubLayer {
        key:Guid,display:Display,flags:u32,provider:*mut Guid,
        provider_data:Blob,weight:u16
    }
    const RPC_C_AUTHN_WINNT:u32=10;
    #[link(name="fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineOpen0(server:*const u16,authn:u32,id:*const c_void,
                           session:*const c_void,engine:*mut *mut c_void)->u32;
        fn FwpmEngineClose0(engine:*mut c_void)->u32;
        fn FwpmSubLayerCreateEnumHandle0(engine:*mut c_void,template:*const c_void,
                                          enumeration:*mut *mut c_void)->u32;
        fn FwpmSubLayerEnum0(engine:*mut c_void,enumeration:*mut c_void,
                             max:u32,entries:*mut *mut *mut SubLayer,count:*mut u32)->u32;
        fn FwpmSubLayerDestroyEnumHandle0(engine:*mut c_void,enumeration:*mut c_void)->u32;
        fn FwpmFreeMemory0(p:*mut *mut c_void);
    }
    struct Engine(*mut c_void);
    impl Drop for Engine {fn drop(&mut self){if !self.0.is_null(){unsafe{let _=FwpmEngineClose0(self.0);}}}}
    struct Enumerator{engine:*mut c_void,handle:*mut c_void}
    impl Enumerator {
        fn finish(mut self)->Result<(),(&'static str,u32)> {
            let e=unsafe{FwpmSubLayerDestroyEnumHandle0(self.engine,self.handle)};
            self.handle=ptr::null_mut();
            if e==0 {Ok(())} else {Err(("destroy",e))}
        }
    }
    impl Drop for Enumerator {fn drop(&mut self){if !self.handle.is_null(){unsafe{
        let _=FwpmSubLayerDestroyEnumHandle0(self.engine,self.handle);
    }}}}
    struct PageBuffer(*mut *mut SubLayer);
    impl Drop for PageBuffer {fn drop(&mut self){if !self.0.is_null(){unsafe{
        let mut p=self.0.cast::<c_void>();FwpmFreeMemory0(&mut p);
    }}}}
    fn scan()->Result<Count,(&'static str,u32)>{
        let mut h=ptr::null_mut();
        let rc=unsafe{FwpmEngineOpen0(ptr::null(),RPC_C_AUTHN_WINNT,
                                      ptr::null(),ptr::null(),&mut h)};
        if rc!=0||h.is_null(){return Err(("open",if rc==0{1}else{rc}));}
        let engine=Engine(h);
        let mut enum_handle=ptr::null_mut();
        let rc=unsafe{FwpmSubLayerCreateEnumHandle0(engine.0,ptr::null(),&mut enum_handle)};
        if rc!=0||enum_handle.is_null(){return Err(("enumerator",if rc==0{1}else{rc}));}
        let enumeration=Enumerator{engine:engine.0,handle:enum_handle};
        let mut counts=Count::default();
        loop {
            let mut array=ptr::null_mut();let mut n=0u32;
            let rc=unsafe{FwpmSubLayerEnum0(engine.0,enumeration.handle,PAGE,&mut array,&mut n)};
            let page=PageBuffer(array);
            if rc!=0{return Err(("enum_page",rc));}
            if n>PAGE||(n>0&&page.0.is_null()){return Err(("page_shape",1));}
            if counts.total.checked_add(u64::from(n)).is_none_or(|v|v>CAP){return Err(("budget",1));}
            if n>0 {
                for &p in unsafe{slice::from_raw_parts(page.0,n as usize)} {
                    if p.is_null(){return Err(("null_entry",1));}
                    let sub=unsafe{&*p};counts.total+=1;
                    if sub.key==Guid::from_u128(OWNER_KEY){
                        counts.owners+=1;
                        if counts.owners>1{return Err(("duplicate_owner",1));}
                        counts.descriptor_ok=sub.weight==OWNER_WEIGHT && sub.flags==0
                            && sub.provider.is_null() && sub.provider_data.size==0
                            && sub.provider_data.data.is_null();
                    }else if sub.weight>OWNER_WEIGHT {counts.higher+=1}
                    else if sub.weight==OWNER_WEIGHT {counts.equal+=1}
                    else {counts.lower+=1}
                }
            }
            if n<PAGE{break;}
        }
        enumeration.finish()?;
        if classify(counts)==2{return Err(("owned_missing_or_changed",1));}
        Ok(counts)
    }
    pub fn run()->i32{
        match scan(){
            Err((stage,code))=>{
                println!("{{\"status\":\"UNKNOWN\",\"stage\":\"{stage}\",\"code\":{code},\"kernel_origin_proof\":false,\"no_direct_proof\":false}}");2
            }
            Ok(c)=>{
                let verdict=classify(c);
                let status=if verdict==3 {"VISIBLE_SUBLAYER_WEIGHT_PEER_UNQUALIFIED"}
                           else {"UNKNOWN_NO_VISIBLE_WEIGHT_PEER"};
                println!("{{\"status\":\"{status}\",\"visible_total\":{},\"foreign_higher\":{},\"foreign_equal\":{},\"foreign_lower\":{},\"owned_descriptor_match_only\":true,\"acl_hidden_possible\":true,\"filters_and_layer_overlap_unverified\":true,\"temporal_join_unverified\":true,\"kernel_origin_proof\":false,\"no_direct_proof\":false}}",
                         c.total,c.higher,c.equal,c.lower);verdict
            }
        }
    }
    #[cfg(test)]mod tests{
        use super::*;
        #[test]fn abi_x64(){
            assert_eq!(std::mem::size_of::<Guid>(),16);
            assert_eq!(std::mem::size_of::<Blob>(),16);
            assert_eq!(std::mem::offset_of!(SubLayer,flags),32);
            assert_eq!(std::mem::offset_of!(SubLayer,provider),40);
            assert_eq!(std::mem::offset_of!(SubLayer,provider_data),48);
            assert_eq!(std::mem::offset_of!(SubLayer,weight),64);
            assert_eq!(std::mem::size_of::<SubLayer>(),72);
        }
    }
}
#[cfg(all(windows,target_pointer_width="64"))]
fn main(){std::process::exit(native::run())}
#[cfg(test)]mod synthetic_tests{
    use super::*;
    fn base()->Count{Count{total:1,owners:1,descriptor_ok:true,..Count::default()}}
    #[test]fn no_visible_peers_still_unknown(){assert_eq!(classify(base()),4)}
    #[test]fn higher_and_equal_are_only_candidates(){
        for (higher,equal) in [(1,0),(0,1),(2,3)]{
            let mut c=base();c.higher=higher;c.equal=equal;c.total+=higher+equal;
            assert_eq!(classify(c),3);
        }
    }
    #[test]fn no_owner_or_malformed_cardinality_is_error(){
        let mut c=base();c.owners=0;assert_eq!(classify(c),2);
        let mut c=base();c.total=2;assert_eq!(classify(c),2);
        let mut c=base();c.descriptor_ok=false;assert_eq!(classify(c),2);
    }
}
