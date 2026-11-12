//! R134: read-only observations of THIS process's image path, held file IDs, WFP AppId.
//! No driver, filter, socket, child, arbitrary PID/path or file mutation.
//! Reopening a reported image name does NOT prove mapped image-section identity.
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
use std::io::{self, Write};
#[repr(C)]
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
struct FileId { volume: u64, id: [u8;16] }
#[repr(C)]
struct Blob { size: u32, data: *mut u8 }
const FILE_ID_INFO: i32 = 18;
const SHARE_READ: u32 = 1;
const BLOB_LIMIT: usize = 65536; // Resource cap, not a claim about the Windows format.
fn local_dos(path: &[u16]) -> Option<Vec<u16>> {
    let p=if path.starts_with(&[92,92,63,92]) {&path[4..]} else {path};
    if p.len()<4 || !((65..=90).contains(&p[0])||(97..=122).contains(&p[0])) ||
        p[1]!=58 || p[2]!=92 || p.contains(&0) || p[2..].contains(&58) {return None;}
    Some(p.to_vec())
}
fn id_usable(id: FileId)->bool { id.id != [0;16] }
fn same_file(a:FileId,b:FileId)->bool {id_usable(a)&&id_usable(b)&&a==b}
fn hex(bytes:&[u8])->String {
    use std::fmt::Write as _;
    let mut s=String::new();for b in bytes{write!(&mut s,"{b:02X}").unwrap();}s
}
fn wide_hex(wide:&[u16])->String {
    use std::fmt::Write as _;
    let mut s=String::new();for n in wide{write!(&mut s,"{n:04X}").unwrap();}s
}
// Bits 0..6: both IDs usable, same file, IDs stable, AppIds nonempty,
// AppIds stable, AppIds equal across names, self-process names stable.
// Bit 7: exact native-name equality is informative only (not a file-ID test).
fn verdict(mask:u8)->i32 {if mask&0x7f==0x7f {0}else{3}}
fn matrix(out:&mut impl Write)->io::Result<()> {
    for m in 0..=255u8 {writeln!(out,"{m:03}:{}",verdict(m))?;}Ok(())
}
#[cfg(all(windows,target_arch="x86_64",not(test)))]
mod win {
    use super::*;
    use std::{ffi::c_void,ptr,slice};
    type Handle=*mut c_void;
    #[link(name="kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess()->Handle;
        fn GetCurrentProcessId()->u32;
        fn QueryFullProcessImageNameW(h:Handle,flags:u32,name:*mut u16,count:*mut u32)->i32;
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
    #[derive(Debug)] struct Error{stage:&'static str,code:u32}
    type Result<T>=std::result::Result<T,Error>;
    fn err(stage:&'static str,code:u32)->Error{Error{stage,code}}
    fn last(stage:&'static str)->Error{err(stage,unsafe{GetLastError()})}
    fn z(path:&[u16])->Vec<u16>{path.iter().copied().chain(Some(0)).collect()}
    fn fixed_dos(path:&[u16])->Result<Vec<u16>> {
        let p=local_dos(path).ok_or_else(||err("not_local_drive_path",0))?;
        let root=[p[0],58,92,0];let kind=unsafe{GetDriveTypeW(root.as_ptr())};
        if kind!=3 {return Err(err("drive_not_fixed",kind));} Ok(p)
    }
    fn process_name(flags:u32)->Result<Vec<u16>> {
        let mut b=vec![0u16;32768];let mut n=b.len()as u32;
        if unsafe{QueryFullProcessImageNameW(GetCurrentProcess(),flags,b.as_mut_ptr(),&mut n)}==0 {
            return Err(last("QueryFullProcessImageNameW"));
        }
        if n==0||n as usize>=b.len(){return Err(err("process_name_length",n));}
        b.truncate(n as usize);if b.contains(&0){return Err(err("process_name_nul",0));}Ok(b)
    }
    struct File(Handle);
    impl File {
        fn open(path:&[u16])->Result<Self>{
            let p=fixed_dos(path)?;let p=z(&p);
            let h=unsafe{CreateFileW(p.as_ptr(),0x80000000,SHARE_READ,ptr::null(),3,0,ptr::null_mut())};
            if h as isize == -1 {Err(last("CreateFileW_read_only"))}else{Ok(Self(h))}
        }
        fn close(mut self)->Result<()>{
            let h=std::mem::replace(&mut self.0,ptr::null_mut());
            if unsafe{CloseHandle(h)}==0 {Err(last("CloseHandle"))}else{Ok(())}
        }
    }
    impl Drop for File{fn drop(&mut self){if !self.0.is_null(){unsafe{let _=CloseHandle(self.0);}}}}
    fn file_id(f:&File)->Result<FileId>{
        let mut id=FileId::default();
        if unsafe{GetFileInformationByHandleEx(f.0,FILE_ID_INFO,(&mut id as *mut FileId).cast(),24)}==0 {
            return Err(last("GetFileInformationByHandleEx_FileIdInfo"));
        }Ok(id)
    }
    fn final_name(f:&File,flags:u32)->Result<Vec<u16>> {
        let mut b=vec![0u16;32768];let n=unsafe{GetFinalPathNameByHandleW(f.0,b.as_mut_ptr(),b.len()as u32,flags)};
        if n==0{return Err(last("GetFinalPathNameByHandleW"));}
        if n as usize>=b.len(){return Err(err("final_name_over_cap",n));}
        b.truncate(n as usize);if b.contains(&0){return Err(err("final_name_nul",0));}Ok(b)
    }
    struct OwnedBlob(*mut Blob);
    impl Drop for OwnedBlob{fn drop(&mut self){if !self.0.is_null(){unsafe{let mut p=self.0.cast::<c_void>();FwpmFreeMemory0(&mut p);}}}}
    fn appid(path:&[u16])->Result<Vec<u8>> {
        let path=z(path);let mut raw=ptr::null_mut();
        let code=unsafe{FwpmGetAppIdFromFileName0(path.as_ptr(),&mut raw)};
        if code!=0{return Err(err("FwpmGetAppIdFromFileName0",code));}
        if raw.is_null(){return Err(err("appid_success_null",0));}
        let owned=OwnedBlob(raw);let blob=unsafe{&*owned.0};
        if blob.size==0||blob.size as usize>BLOB_LIMIT||blob.data.is_null(){return Err(err("appid_blob_shape",blob.size));}
        // OPAQUE bytes; no UTF16/NUL/terminator interpretation is required here.
        Ok(unsafe{slice::from_raw_parts(blob.data,blob.size as usize)}.to_vec())
    }
    struct Data{pid:u32,pdos:Vec<u16>,pnt:Vec<u16>,names_stable:bool,
        dos:[Vec<u16>;2],nt:[Vec<u16>;2],before:[FileId;2],after:[FileId;2],apps:[Vec<u8>;4],mask:u8}
    fn read()->Result<Data>{
        let pdos=process_name(0)?;let pnt=process_name(1)?;
        let original=fixed_dos(&pdos)?;let first=File::open(&original)?;
        let dos0=final_name(&first,0)?;let nt0=final_name(&first,2)?;
        let canonical=fixed_dos(&dos0)?;let second=File::open(&canonical)?;
        let dos1=final_name(&second,0)?;let nt1=final_name(&second,2)?;
        let before=[file_id(&first)?,file_id(&second)?];
        let apps=[appid(&original)?,appid(&canonical)?,appid(&original)?,appid(&canonical)?];
        let after=[file_id(&first)?,file_id(&second)?];
        let names_stable=pdos==process_name(0)? && pnt==process_name(1)?;
        let flags=[id_usable(before[0])&&id_usable(before[1]),same_file(before[0],before[1]),
            before==after,apps.iter().all(|a|!a.is_empty()),apps[0]==apps[2]&&apps[1]==apps[3],
            apps[0]==apps[1],names_stable,pnt==nt0&&pnt==nt1];
        let mut mask=0;for(i,f)in flags.iter().enumerate(){if *f{mask|=1<<i;}}
        let pid=unsafe{GetCurrentProcessId()};
        // No transaction/atomicity claim. Both pins were held over the four AppId queries.
        second.close()?;first.close()?;
        Ok(Data{pid,pdos,pnt,names_stable,dos:[dos0,dos1],nt:[nt0,nt1],before,after,apps,mask})
    }
    pub fn run()->i32{
        match read(){Err(e)=>{
            println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"QUERY_ERROR\",\"stage\":\"{}\",\"code\":{},\"code_hex\":\"0x{:08X}\",\"kernel_origin_proof\":false,\"image_section_identity_proof\":false,\"no_direct_proof\":false}}",e.stage,e.code,e.code);2
        },Ok(d)=>{
            println!("{{\"schema\":1,\"kind\":\"self_process\",\"pid\":{},\"dos_name_hex\":\"{}\",\"native_name_hex\":\"{}\",\"names_stable\":{},\"kernel_origin_proof\":false,\"image_section_identity_proof\":false,\"no_direct_proof\":false}}",d.pid,wide_hex(&d.pdos),wide_hex(&d.pnt),d.names_stable);
            for i in 0..2 {println!("{{\"schema\":1,\"kind\":\"file\",\"index\":{i},\"volume_before\":\"{:016X}\",\"id_before\":\"{}\",\"volume_after\":\"{:016X}\",\"id_after\":\"{}\",\"final_dos_hex\":\"{}\",\"final_native_hex\":\"{}\",\"kernel_origin_proof\":false,\"image_section_identity_proof\":false,\"no_direct_proof\":false}}",d.before[i].volume,hex(&d.before[i].id),d.after[i].volume,hex(&d.after[i].id),wide_hex(&d.dos[i]),wide_hex(&d.nt[i]));}
            println!("{{\"schema\":1,\"kind\":\"appid\",\"queries\":4,\"process_path_before\":\"{}\",\"final_path_before\":\"{}\",\"process_path_after\":\"{}\",\"final_path_after\":\"{}\",\"opaque_bytes\":true,\"kernel_origin_proof\":false,\"image_section_identity_proof\":false,\"no_direct_proof\":false}}",hex(&d.apps[0]),hex(&d.apps[1]),hex(&d.apps[2]),hex(&d.apps[3]));
            let code=verdict(d.mask);let status=if code==0{"SELF_IMAGE_FILE_APPID_OBSERVED_NOT_ALE_PROOF"}else{"OBSERVATION_MISMATCH_NO_PROOF"};
            println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"{status}\",\"observations_mask\":{},\"diagnostic_exit\":{code},\"share_mode\":1,\"file_id_class\":18,\"read_only_file_handles\":2,\"atomic_snapshot\":false,\"kernel_origin_proof\":false,\"image_section_identity_proof\":false,\"no_direct_proof\":false}}",d.mask);code
        }}
    }
}
fn main(){
    let args:Vec<_>=std::env::args().skip(1).collect();
    if args==["--contract-matrix"]{if matrix(&mut io::stdout().lock()).is_err(){std::process::exit(2);}return;}
    #[cfg(all(windows,target_arch="x86_64",not(test)))]
    if args==["--self-image-probe"]{std::process::exit(win::run());}
    eprintln!("usage: --contract-matrix | --self-image-probe (Windows x64)");std::process::exit(2);
}
#[cfg(test)]mod tests{
    use super::*;
    fn p(s:&str)->Vec<u16>{s.encode_utf16().collect()}
    fn id()->FileId{FileId{volume:1,id:[2;16]}}
    #[test]fn file_id_abi(){assert_eq!(std::mem::size_of::<FileId>(),24);assert_eq!(std::mem::align_of::<FileId>(),8);assert_eq!(std::mem::offset_of!(FileId,id),8);}
    #[test]fn blob_abi_x64(){assert_eq!(std::mem::size_of::<Blob>(),16);assert_eq!(std::mem::offset_of!(Blob,data),8);}
    #[test]fn exact_file_id_matches(){assert!(same_file(id(),id()));}
    #[test]fn volume_alone_not_identity(){let mut b=id();b.id[15]=3;assert!(!same_file(id(),b));}
    #[test]fn id_without_volume_not_identity(){let mut b=id();b.volume=7;assert!(!same_file(id(),b));}
    #[test]fn zero_file_id_is_unknown(){assert!(!same_file(FileId::default(),FileId::default()));}
    #[test]fn disk_path_preserved(){assert_eq!(local_dos(&p(r"C:\probe.exe")),Some(p(r"C:\probe.exe")));}
    #[test]fn verified_extended_prefix_only(){assert_eq!(local_dos(&p(r"\\?\C:\probe.exe")),Some(p(r"C:\probe.exe")));}
    #[test]fn unc_rejected(){for s in [r"\\server\share\probe.exe",r"\\?\UNC\server\share\probe.exe"]{assert!(local_dos(&p(s)).is_none());}}
    #[test]fn relative_and_native_not_dos(){for s in [r"C:probe.exe",r"probe.exe",r"\Device\HarddiskVolume1\probe.exe"]{assert!(local_dos(&p(s)).is_none());}}
    #[test]fn nul_and_ads_rejected(){for s in ["C:\\p\0.exe",r"C:\p.exe:data"]{assert!(local_dos(&p(s)).is_none());}}
    #[test]fn no_casefold_or_trim(){assert_eq!(local_dos(&p(r"c:\AbC.exe")),Some(p(r"c:\AbC.exe")));}
    #[test]fn opaque_bytes_not_decoded(){assert_eq!(hex(&[0xff,0,0xd8]),"FF00D8");}
    #[test]fn wide_hex_lossless(){assert_eq!(wide_hex(&[0xd800,0x41]),"D8000041");}
    #[test]fn all_core_checks_required(){assert_eq!(verdict(127),0);for i in 0..7{assert_eq!(verdict(127^(1<<i)),3);}}
    #[test]fn native_string_equality_not_file_proof(){assert_eq!(verdict(255),0);assert_eq!(verdict(128),3);assert_eq!(verdict(127),0);}
    #[test]fn same_appid_alone_not_identity(){assert_eq!(verdict(1<<5),3);}
    #[test]fn matrix_cardinality(){let mut out=Vec::new();matrix(&mut out).unwrap();let s=String::from_utf8(out).unwrap();assert_eq!(s.lines().count(),256);assert_eq!(s.lines().filter(|x|x.ends_with(":0")).count(),2);}
}
