//! R136: own process's loaded main image (MEM_IMAGE + mapped path) versus
//! current image names and a read-only reopened file. NOT mapped-section file ID.
//! No driver, WFP filter, sockets, process enumeration, image modification.
#![deny(unsafe_op_in_unsafe_fn)]
use std::io::{self, Write};
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FileId { volume: u64, id: [u8;16] }
#[repr(C)]
struct Blob { size: u32, data: *mut u8 }
const MEM_IMAGE:u32=0x01000000;
const MEM_COMMIT:u32=0x00001000;
const FILE_ID_INFO:i32=18;
const FWP_BLOB_LIMIT:usize=65536;
fn core_exit(mask:u8)->i32 { if (mask&127)==127 {0} else {3} }
fn matrix(w:&mut impl Write)->io::Result<()> { for m in 0..=255u8 {writeln!(w,"{m:03}:{}",core_exit(m))?;} Ok(()) }
fn useful_id(id:FileId)->bool {id.volume!=0 && id.id != [0;16]}
fn id_stable(a:FileId,b:FileId)->bool {useful_id(a) && a==b}
fn same_nonempty(a:&[u16],b:&[u16])->bool {!a.is_empty()&&a==b}
fn appids_agree(a:&[Vec<u8>;4])->bool {!a[0].is_empty()&&a.iter().all(|x| x==&a[0])}
fn local_drive(path:&[u16])->Option<Vec<u16>> {
    let p=if path.starts_with(&[92,92,63,92]){&path[4..]}else{path};
    if p.len()<4 || !((65..=90).contains(&p[0])||(97..=122).contains(&p[0])) || p[1]!=58 || p[2]!=92 ||
       p.contains(&0) || p[3..].contains(&58) {return None;}
    Some(p.to_vec())
}
fn upper_hex(bytes:&[u8])->String {
    use std::fmt::Write as _;let mut s=String::new();for b in bytes{write!(&mut s,"{b:02X}").unwrap();}s
}
fn hex_u16(wide:&[u16])->String {
    use std::fmt::Write as _;let mut s=String::new();for w in wide{write!(&mut s,"{w:04X}").unwrap();}s
}
#[cfg(all(windows,target_arch="x86_64",not(test)))]
mod win {
    use super::*;
    use std::{ffi::c_void,mem,ptr,slice};
    type Handle=*mut c_void;
    #[repr(C)]
    struct Mbi {
        base:*const c_void,allocation_base:*const c_void,allocation_protect:u32,
        partition_id:u16,align:u16,region_size:usize,state:u32,protect:u32,kind:u32,pad:u32
    }
    #[link(name="kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess()->Handle;
        fn GetCurrentProcessId()->u32;
        fn GetModuleHandleW(name:*const u16)->Handle;
        fn GetModuleFileNameW(module:Handle,name:*mut u16,capacity:u32)->u32;
        fn QueryFullProcessImageNameW(h:Handle,flags:u32,name:*mut u16,count:*mut u32)->i32;
        fn K32GetMappedFileNameW(h:Handle,address:*const c_void,name:*mut u16,capacity:u32)->u32;
        fn VirtualQuery(address:*const c_void,information:*mut Mbi,length:usize)->usize;
        fn GetDriveTypeW(root:*const u16)->u32;
        fn CreateFileW(name:*const u16,access:u32,share:u32,security:*const c_void,
                       disposition:u32,flags:u32,template:Handle)->Handle;
        fn GetFileInformationByHandleEx(h:Handle,class:i32,out:*mut c_void,size:u32)->i32;
        fn GetFinalPathNameByHandleW(h:Handle,out:*mut u16,count:u32,flags:u32)->u32;
        fn CloseHandle(h:Handle)->i32;
        fn GetLastError()->u32;
    }
    #[link(name="fwpuclnt")]
    unsafe extern "system" {
        fn FwpmGetAppIdFromFileName0(name:*const u16,out:*mut *mut Blob)->u32;
        fn FwpmFreeMemory0(out:*mut *mut c_void);
    }
    #[derive(Debug)] struct Failure{stage:&'static str,code:u32}
    type Result<T>=std::result::Result<T,Failure>;
    fn fail(stage:&'static str,code:u32)->Failure {Failure{stage,code}}
    fn last(stage:&'static str)->Failure {fail(stage,unsafe{GetLastError()})}
    fn z(w:&[u16])->Vec<u16> {w.iter().copied().chain(Some(0)).collect()}
    fn qname(flags:u32)->Result<Vec<u16>> {
        let mut buf=vec![0u16;32768];let mut cap=buf.len()as u32;
        if unsafe{QueryFullProcessImageNameW(GetCurrentProcess(),flags,buf.as_mut_ptr(),&mut cap)}==0 {return Err(last("QueryFullProcessImageNameW"));}
        if cap==0||cap as usize>=buf.len(){return Err(fail("qname_size",cap));}
        buf.truncate(cap as usize);if buf.contains(&0){return Err(fail("qname_nul",0));}Ok(buf)
    }
    fn module_name(h:Handle)->Result<Vec<u16>> {
        let mut buf=vec![0u16;32768];let n=unsafe{GetModuleFileNameW(h,buf.as_mut_ptr(),buf.len()as u32)};
        if n==0{return Err(last("GetModuleFileNameW"));}
        if n as usize>=buf.len(){return Err(fail("module_name_truncated",n));}
        buf.truncate(n as usize);if buf.contains(&0){return Err(fail("module_name_nul",0));}Ok(buf)
    }
    fn mapped_name(base:Handle)->Result<Vec<u16>> {
        let mut buf=vec![0u16;32768];let n=unsafe{K32GetMappedFileNameW(GetCurrentProcess(),base.cast_const(),buf.as_mut_ptr(),buf.len()as u32)};
        if n==0{return Err(last("K32GetMappedFileNameW"));}
        if n as usize>=buf.len(){return Err(fail("mapped_name_truncated",n));}
        buf.truncate(n as usize);if buf.contains(&0){return Err(fail("mapped_name_nul",0));}Ok(buf)
    }
    fn fixed(path:&[u16])->Result<Vec<u16>> {
        let p=local_drive(path).ok_or_else(||fail("not_local_drive",0))?;
        let root=[p[0],58,92,0];let k=unsafe{GetDriveTypeW(root.as_ptr())};
        if k!=3 {return Err(fail("not_fixed_drive",k));}Ok(p)
    }
    struct File(Handle);
    impl File{
        fn open(path:&[u16])->Result<Self>{
            let p=z(&fixed(path)?);
            let h=unsafe{CreateFileW(p.as_ptr(),0x80000000,1,ptr::null(),3,0,ptr::null_mut())};
            if h as isize == -1 {Err(last("CreateFileW_GENERIC_READ_SHARE_READ"))}else{Ok(Self(h))}
        }
        fn finish(mut self)->Result<()> {
            let h=mem::replace(&mut self.0,ptr::null_mut());
            if unsafe{CloseHandle(h)}==0{Err(last("CloseHandle"))}else{Ok(())}
        }
    }
    impl Drop for File{fn drop(&mut self){if !self.0.is_null(){unsafe{let _=CloseHandle(self.0);}}}}
    fn fid(f:&File)->Result<FileId>{
        let mut id=FileId::default();
        if unsafe{GetFileInformationByHandleEx(f.0,FILE_ID_INFO,(&mut id as *mut FileId).cast(),24)}==0{return Err(last("GetFileInformationByHandleEx"));}Ok(id)
    }
    fn final_path(f:&File,flags:u32)->Result<Vec<u16>> {
        let mut buf=vec![0u16;32768];
        let n=unsafe{GetFinalPathNameByHandleW(f.0,buf.as_mut_ptr(),buf.len()as u32,flags)};
        if n==0{return Err(last("GetFinalPathNameByHandleW"));}
        if n as usize>=buf.len(){return Err(fail("final_path_truncated",n));}
        buf.truncate(n as usize);if buf.contains(&0){return Err(fail("final_path_nul",0));}Ok(buf)
    }
    struct OwnedBlob(*mut Blob);
    impl Drop for OwnedBlob{fn drop(&mut self){if !self.0.is_null(){unsafe{let mut p=self.0.cast::<c_void>();FwpmFreeMemory0(&mut p);}}}}
    fn appid(path:&[u16])->Result<Vec<u8>>{
        let p=z(path);let mut raw=ptr::null_mut();
        let status=unsafe{FwpmGetAppIdFromFileName0(p.as_ptr(),&mut raw)};
        if status!=0{return Err(fail("FwpmGetAppIdFromFileName0",status));}
        if raw.is_null(){return Err(fail("appid_null",0));}
        let blob=OwnedBlob(raw);let d=unsafe{&*blob.0};
        if d.size==0||d.size as usize>FWP_BLOB_LIMIT||d.data.is_null(){return Err(fail("appid_shape",d.size));}
        Ok(unsafe{slice::from_raw_parts(d.data,d.size as usize)}.to_vec())
    }
    struct Data{pid:u32,q0:Vec<u16>,q1:Vec<u16>,n0:Vec<u16>,n1:Vec<u16>,module_name:Vec<u16>,
        mapped0:Vec<u16>,mapped1:Vec<u16>,mbi_state:u32,mbi_kind:u32,base_address:usize,allocation_base_address:usize,
        file_native:Vec<u16>,file_dos:Vec<u16>,id0:FileId,id1:FileId,apps:[Vec<u8>;4],mask:u8}
    fn inspect()->Result<Data>{
        let q0=qname(0)?;let n0=qname(1)?;
        let base=unsafe{GetModuleHandleW(ptr::null())};
        if base.is_null(){return Err(last("GetModuleHandleW_self"));}
        let modname=module_name(base)?;
        let mut mbi=Mbi{base:ptr::null(),allocation_base:ptr::null(),allocation_protect:0,partition_id:0,align:0,
            region_size:0,state:0,protect:0,kind:0,pad:0};
        if unsafe{VirtualQuery(base.cast_const(),&mut mbi,mem::size_of::<Mbi>())}!=mem::size_of::<Mbi>(){
            return Err(last("VirtualQuery_image_base"));
        }
        let mapped0=mapped_name(base)?;
        let f=File::open(&q0)?;
        let file_dos=final_path(&f,0)?;let file_native=final_path(&f,2)?;
        let id0=fid(&f)?;
        let app_dos=fixed(&file_dos)?;
        let apps=[appid(&q0)?,appid(&app_dos)?,appid(&q0)?,appid(&app_dos)?];
        let id1=fid(&f)?;
        let mapped1=mapped_name(base)?;
        let q1=qname(0)?;let n1=qname(1)?;
        f.finish()?;
        let flags=[mbi.state==MEM_COMMIT && mbi.kind==MEM_IMAGE && mbi.allocation_base==base.cast_const(),
            same_nonempty(&mapped0,&mapped1),
            same_nonempty(&mapped0,&n0) && n0==n1,
            same_nonempty(&mapped0,&file_native),
            id_stable(id0,id1),
            appids_agree(&apps),
            same_nonempty(&q0,&q1),
            same_nonempty(&modname,&q0)];
        let mut mask=0;for(i,yes)in flags.iter().enumerate(){if *yes{mask|=1<<i;}}
        Ok(Data{pid:unsafe{GetCurrentProcessId()},q0,q1,n0,n1,module_name:modname,mapped0,mapped1,
            mbi_state:mbi.state,mbi_kind:mbi.kind,base_address:base as usize,allocation_base_address:mbi.allocation_base as usize,
            file_native,file_dos,id0,id1,apps,mask})
    }
    const BOUND:&str="\"kernel_origin_proof\":false,\"mapped_section_file_id_proof\":false,\"network_owner_proof\":false,\"no_direct_proof\":false";
    pub fn run()->i32{
        match inspect(){Err(e)=>{println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"QUERY_ERROR\",\"stage\":\"{}\",\"win32_error_or_wfp_status\":{},{} }}",e.stage,e.code,BOUND);2},
        Ok(x)=>{
            println!("{{\"schema\":1,\"kind\":\"self\",\"pid\":{},\"win32_before\":\"{}\",\"win32_after\":\"{}\",\"native_before\":\"{}\",\"native_after\":\"{}\",\"module_name\":\"{}\",{} }}",x.pid,hex_u16(&x.q0),hex_u16(&x.q1),hex_u16(&x.n0),hex_u16(&x.n1),hex_u16(&x.module_name),BOUND);
            println!("{{\"schema\":1,\"kind\":\"mapping\",\"mapped_native_before\":\"{}\",\"mapped_native_after\":\"{}\",\"state\":{},\"type\":{},\"module_base_hex\":\"{:016X}\",\"allocation_base_hex\":\"{:016X}\",{} }}",hex_u16(&x.mapped0),hex_u16(&x.mapped1),x.mbi_state,x.mbi_kind,x.base_address,x.allocation_base_address,BOUND);
            println!("{{\"schema\":1,\"kind\":\"file\",\"final_native\":\"{}\",\"final_dos\":\"{}\",\"volume_before\":\"{:016X}\",\"volume_after\":\"{:016X}\",\"id_before\":\"{}\",\"id_after\":\"{}\",\"app0\":\"{}\",\"app1\":\"{}\",\"app2\":\"{}\",\"app3\":\"{}\",{} }}",hex_u16(&x.file_native),hex_u16(&x.file_dos),x.id0.volume,x.id1.volume,upper_hex(&x.id0.id),upper_hex(&x.id1.id),upper_hex(&x.apps[0]),upper_hex(&x.apps[1]),upper_hex(&x.apps[2]),upper_hex(&x.apps[3]),BOUND);
            let code=core_exit(x.mask);let name=if code==0{"MAPPED_IMAGE_NAME_CONCORDANT_NOT_SECTION_FILE_ID_PROOF"}else{"MAPPING_OBSERVATION_MISMATCH_NO_PROOF"};
            println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"{}\",\"observation_mask\":{},\"diagnostic_exit\":{},\"mem_image_constant\":{},\"file_id_class\":{},\"atomic_snapshot\":false,{} }}",name,x.mask,code,MEM_IMAGE,FILE_ID_INFO,BOUND);
            code
        }}
    }
}
fn main(){let args:Vec<_>=std::env::args().skip(1).collect();
    if args==["--contract-matrix"]{if matrix(&mut io::stdout().lock()).is_err(){std::process::exit(2);}return;}
    #[cfg(all(windows,target_arch="x86_64",not(test)))]
    if args==["--self-mapped-image"]{std::process::exit(win::run());}
    eprintln!("usage: --contract-matrix | --self-mapped-image (Windows x86_64)");std::process::exit(2);
}
#[cfg(test)] mod tests{
    use super::*;
    fn w(s:&str)->Vec<u16>{s.encode_utf16().collect()}
    fn id()->FileId{FileId{volume:0x123,id:[3;16]}}
    #[test]fn file_id_abi_x64(){assert_eq!(std::mem::size_of::<FileId>(),24);assert_eq!(std::mem::offset_of!(FileId,id),8);}
    #[test]fn blob_abi_x64(){assert_eq!(std::mem::size_of::<Blob>(),16);assert_eq!(std::mem::offset_of!(Blob,data),8);}
    #[test]fn named_disk_path(){assert_eq!(local_drive(&w(r"C:\Folder\app.exe")),Some(w(r"C:\Folder\app.exe")));}
    #[test]fn extended_prefix(){assert_eq!(local_drive(&w(r"\\?\C:\Folder\app.exe")),Some(w(r"C:\Folder\app.exe")));}
    #[test]fn reject_unc(){assert!(local_drive(&w(r"\\Server\a.exe")).is_none());}
    #[test]fn reject_native(){assert!(local_drive(&w(r"\Device\HarddiskVolume3\a.exe")).is_none());}
    #[test]fn reject_relative(){assert!(local_drive(&w(r"C:a.exe")).is_none());}
    #[test]fn reject_ads(){assert!(local_drive(&w(r"C:\a.exe:ads")).is_none());}
    #[test]fn reject_nul(){assert!(local_drive(&[67,58,92,97,0,98]).is_none());}
    #[test]fn id_both_require_nonzero(){assert!(useful_id(id()));assert!(!useful_id(FileId::default()));}
    #[test]fn zero_volume_invalid(){let mut i=id();i.volume=0;assert!(!useful_id(i));}
    #[test]fn stable_id_detects_change(){let mut j=id();j.id[0]=4;assert!(!id_stable(id(),j));}
    #[test]fn stable_id_requires_nonzero(){assert!(!id_stable(FileId::default(),FileId::default()));}
    #[test]fn empty_mapping_name_invalid(){assert!(!same_nonempty(&[],&[]));}
    #[test]fn appid_binary_nonempty(){assert!(appids_agree(&[vec![0xff,0],vec![0xff,0],vec![0xff,0],vec![0xff,0]]));}
    #[test]fn appid_drift_invalid(){assert!(!appids_agree(&[vec![1],vec![1],vec![2],vec![1]]));}
    #[test]fn optional_module_name_not_identity(){assert_eq!(core_exit(127),0);assert_eq!(core_exit(255),0);}
    #[test]fn no_single_required_bit_can_be_ignored(){for i in 0..7 {assert_eq!(core_exit(127^(1<<i)),3);}}
    #[test]fn decision_matrix_256(){let mut b=vec![];matrix(&mut b).unwrap();let s=String::from_utf8(b).unwrap();assert_eq!(s.lines().count(),256);assert_eq!(s.lines().filter(|x|x.ends_with(":0")).count(),2);}
    #[test]fn raw_utf16_units_lossless(){assert_eq!(hex_u16(&[0xd800,0x0041]),"D8000041");}
    #[test]fn opaque_appid_hex(){assert_eq!(upper_hex(&[0xff,0,0xd8]),"FF00D8");}
}
