//! R138: two OWN concurrent helpers, one filename AppId, distinct retained identities.
//! No network sockets, WFP policy, driver, injected process, or arbitrary PID/path.
//! Per-EXE policy may legitimately select both; a process-specific receipt must not.
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
use std::io::{self, Write};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity { pid: u32, created: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sample { id: Identity, before: u32, after: u32, exit: u32 }
fn eligible(expected: Identity, got: Sample, same_app: bool) -> bool {
    expected.pid != 0 && expected.created != 0 && got.id == expected &&
        got.before == 258 && got.after == 258 && got.exit == 259 && same_app
}
fn matrix(out: &mut impl Write) -> io::Result<()> {
    for (ep,et) in [(7,11),(7,0),(0,11),(0,0)] {
        for (cp,ct) in [(7,11),(8,11),(7,12),(8,12),(0,0)] {
            for (w0,w1) in [(258,258),(0,0),(258,0),(0,258),(u32::MAX,u32::MAX),(128,128)] {
                for exit in [259,23] { for app in [false,true] {
                    let expected=Identity{pid:ep,created:et};
                    let s=Sample{id:Identity{pid:cp,created:ct},before:w0,after:w1,exit};
                    writeln!(out,"{ep}:{et}:{cp}:{ct}:{w0}:{w1}:{exit}:{}:{}",u8::from(app),u8::from(eligible(expected,s,app)))?;
                }}
            }
        }
    } Ok(())
}
#[cfg(all(windows,target_arch="x86_64",not(test)))]
mod win {
    use super::*;
    use std::{ffi::c_void,os::windows::io::AsRawHandle,process::{Child,Command,Stdio},
        ptr,slice,sync::mpsc,time::Duration};
    use std::io::Read;
    type Handle=*mut c_void;
    #[repr(C)] #[derive(Default)] struct FileTime{low:u32,high:u32}
    #[repr(C)] struct Blob{size:u32,data:*mut u8}
    #[link(name="kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access:u32,inherit:i32,pid:u32)->Handle;
        fn CloseHandle(h:Handle)->i32;
        fn GetProcessId(h:Handle)->u32;
        fn GetProcessTimes(h:Handle,c:*mut FileTime,e:*mut FileTime,k:*mut FileTime,u:*mut FileTime)->i32;
        fn QueryFullProcessImageNameW(h:Handle,flags:u32,out:*mut u16,len:*mut u32)->i32;
        fn GetDriveTypeW(root:*const u16)->u32;
        fn WaitForSingleObject(h:Handle,ms:u32)->u32;
        fn GetExitCodeProcess(h:Handle,out:*mut u32)->i32;
        fn GetLastError()->u32;
    }
    #[link(name="fwpuclnt")]
    unsafe extern "system" {
        fn FwpmGetAppIdFromFileName0(name:*const u16,out:*mut *mut Blob)->u32;
        fn FwpmFreeMemory0(out:*mut *mut c_void);
    }
    #[derive(Debug)] struct Error{domain:&'static str,stage:&'static str,code:u32}
    type Result<T>=std::result::Result<T,Error>;
    fn fail(stage:&'static str)->Error{Error{domain:"observation",stage,code:0}}
    fn api(stage:&'static str,code:u32)->Error{Error{domain:"api",stage,code}}
    fn last(stage:&'static str)->Error{api(stage,unsafe{GetLastError()})}
    fn ioe(stage:&'static str,e:io::Error)->Error{Error{domain:"io",stage,code:e.raw_os_error().unwrap_or(0)as u32}}
    fn wait(h:Handle,ms:u32)->Result<u32>{let w=unsafe{WaitForSingleObject(h,ms)};if w==u32::MAX{Err(last("WaitForSingleObject"))}else{Ok(w)}}
    fn sample(h:Handle)->Result<Sample>{
        let before=wait(h,0)?;let pid=unsafe{GetProcessId(h)};
        if pid==0{return Err(last("GetProcessId"));}
        let(mut c,mut e,mut k,mut u)=(FileTime::default(),FileTime::default(),FileTime::default(),FileTime::default());
        if unsafe{GetProcessTimes(h,&mut c,&mut e,&mut k,&mut u)}==0{return Err(last("GetProcessTimes"));}
        // Exit FILETIME is undefined for a live process and is deliberately unused.
        let created=(u64::from(c.high)<<32)|u64::from(c.low);let mut exit=0;
        if unsafe{GetExitCodeProcess(h,&mut exit)}==0{return Err(last("GetExitCodeProcess"));}
        let after=wait(h,0)?;
        if created==0{return Err(fail("zero_creation_time"));}
        Ok(Sample{id:Identity{pid,created},before,after,exit})
    }
    struct ReadHandle(Handle);
    impl ReadHandle{
        fn close(mut self)->Result<()>{let h=std::mem::replace(&mut self.0,ptr::null_mut());if unsafe{CloseHandle(h)}==0{Err(last("CloseHandle"))}else{Ok(())}}
    }
    impl Drop for ReadHandle{fn drop(&mut self){if !self.0.is_null(){unsafe{let _=CloseHandle(self.0);}}}}
    struct Helper{child:Child,read:Option<ReadHandle>}
    impl Drop for Helper{fn drop(&mut self){drop(self.child.stdin.take());}}
    impl Helper{
        fn spawn(code:&str)->Result<Self>{
            let exe=std::env::current_exe().map_err(|e|ioe("current_exe",e))?;
            let child=Command::new(exe).arg("--child").arg(code).stdin(Stdio::piped())
                .stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e|ioe("spawn_own_helper",e))?;
            let mut own=Self{child,read:None};
            // Only the PID from our OWN Child; original process handle is already held.
            let h=unsafe{OpenProcess(0x0010_1000,0,own.child.id())};
            if h.is_null(){return Err(last("OpenProcess_own_helper"));}
            own.read=Some(ReadHandle(h));Ok(own)
        }
        fn query_handle(&self)->Handle{self.read.as_ref().expect("owned query handle").0}
        fn paired(&self)->Result<Sample>{
            let a=sample(self.child.as_raw_handle())?;let b=sample(self.query_handle())?;
            if a!=b||a.id.pid!=self.child.id(){return Err(fail("primary_secondary_disagree"));}Ok(a)
        }
        fn release_and_wait(&mut self,code:i32)->Result<Sample>{
            let mut pipe=self.child.stdin.take().ok_or_else(||fail("child_stdin_missing"))?;
            pipe.write_all(b"G").map_err(|e|ioe("release_helper",e))?;drop(pipe);
            if wait(self.child.as_raw_handle(),10000)?!=0{return Err(fail("helper_exit_timeout"));}
            let s=self.paired()?;
            if s.before!=0||s.after!=0||s.exit!=code as u32{return Err(fail("helper_exit_state"));}
            let status=self.child.try_wait().map_err(|e|ioe("try_wait",e))?.ok_or_else(||fail("exit_status_missing"))?;
            if status.code()!=Some(code){return Err(fail("exit_status_mismatch"));}Ok(s)
        }
        fn close_read(&mut self)->Result<()>{self.read.take().ok_or_else(||fail("query_handle_missing"))?.close()}
    }
    fn name(h:Handle)->Result<Vec<u16>>{
        let mut b=vec![0u16;32768];let mut n=b.len()as u32;
        if unsafe{QueryFullProcessImageNameW(h,0,b.as_mut_ptr(),&mut n)}==0{return Err(last("QueryFullProcessImageNameW"));}
        if n<4||n as usize>=b.len(){return Err(fail("name_length"));}b.truncate(n as usize);
        let disk=b[1]==58&&b[2]==92&&((65..=90).contains(&b[0])||(97..=122).contains(&b[0]));
        if !disk||b.contains(&0)||b[2..].contains(&58){return Err(fail("not_plain_local_drive_name"));}
        let root=[b[0],58,92,0];if unsafe{GetDriveTypeW(root.as_ptr())}!=3{return Err(fail("not_fixed_drive"));}
        Ok(b)
    }
    struct AppAllocation(*mut Blob);
    impl Drop for AppAllocation{fn drop(&mut self){if !self.0.is_null(){unsafe{let mut p=self.0.cast::<c_void>();FwpmFreeMemory0(&mut p);}}}}
    fn appid(path:&[u16])->Result<Vec<u8>>{
        let z:Vec<_>=path.iter().copied().chain(Some(0)).collect();let mut p=ptr::null_mut();
        let code=unsafe{FwpmGetAppIdFromFileName0(z.as_ptr(),&mut p)};
        if code!=0{return Err(api("FwpmGetAppIdFromFileName0",code));}
        if p.is_null(){return Err(fail("appid_success_null"));}let owned=AppAllocation(p);
        let b=unsafe{&*owned.0};
        if b.size==0||b.size>65536||b.data.is_null(){return Err(fail("appid_shape"));}
        Ok(unsafe{slice::from_raw_parts(b.data,b.size as usize)}.to_vec())
    }
    fn require_live(s:Sample)->Result<()>{if eligible(s.id,s,true){Ok(())}else{Err(fail("helper_not_live_at_reads"))}}
    struct Data{samples:[Sample;5],names:[Vec<u16>;3],apps:[Vec<u8>;4],binding:u8,weak:u8}
    fn experiment()->Result<Data>{
        let mut a=Helper::spawn("23")?;let mut b=Helper::spawn("29")?;
        let a0=a.paired()?;let b0=b.paired()?;require_live(a0)?;require_live(b0)?;
        // Creation times may coincide. Distinct live PIDs, not unequal timestamps, are required.
        if a0.id.pid==b0.id.pid{return Err(fail("live_pid_collision"));}
        let na=name(a.query_handle())?;let nb=name(b.query_handle())?;
        let appa=appid(&na)?;let appb=appid(&nb)?;
        if a.paired()?!=a0||b.paired()?!=b0{return Err(fail("pre_release_state_changed"));}
        let dead_a=a.release_and_wait(23)?;
        let live_b=b.paired()?;require_live(live_b)?;let nb_after=name(b.query_handle())?;
        // Intentionally lookup A's STORED filename after A has exited, NOT its image handle.
        let after_a=appid(&na)?;let after_b=appid(&nb_after)?;
        if a.paired()?!=dead_a||b.paired()?!=live_b{return Err(fail("post_release_state_changed"));}
        let dead_b=b.release_and_wait(29)?;
        if dead_a.id!=a0.id||live_b.id!=b0.id||dead_b.id!=b0.id{return Err(fail("retained_identity_changed"));}
        let apps=[appa,appb,after_a,after_b];
        if na!=nb||nb!=nb_after||apps.iter().any(|v|v!=&apps[0]){return Err(fail("same_image_or_appid_not_observed"));}
        let samples=[a0,b0,dead_a,live_b,dead_b];let mut binding=0;let mut weak=0;
        for i in 0..4{let equal=apps[i]==apps[0];if eligible(a0.id,samples[i],equal){binding|=1<<i;}if equal{weak|=1<<i;}}
        if binding!=1||weak!=15{return Err(fail("binding_counterexample_not_observed"));}
        a.close_read()?;b.close_read()?;
        Ok(Data{samples,names:[na,nb,nb_after],apps,binding,weak})
    }
    fn hex(b:&[u8])->String{use std::fmt::Write as _;let mut s=String::new();for x in b{write!(&mut s,"{x:02X}").unwrap();}s}
    fn wide(w:&[u16])->String{use std::fmt::Write as _;let mut s=String::new();for x in w{write!(&mut s,"{x:04X}").unwrap();}s}
    pub fn run()->i32{
        match experiment(){Err(e)=>{println!("{{\"schema\":1,\"kind\":\"error\",\"domain\":\"{}\",\"stage\":\"{}\",\"code\":{},\"code_hex\":\"0x{:08X}\",\"kernel_origin_proof\":false,\"socket_binding_proof\":false,\"no_direct_proof\":false}}",e.domain,e.stage,e.code,e.code);2},
        Ok(d)=>{
            for (i,(subject,phase)) in [("A","both_alive"),("B","both_alive"),("A","A_exited"),("B","B_survives"),("B","both_exited")].iter().enumerate(){
                let s=d.samples[i];println!("{{\"schema\":1,\"kind\":\"process\",\"subject\":\"{subject}\",\"phase\":\"{phase}\",\"pid\":{},\"creation_hex\":\"{:016X}\",\"wait_before\":{},\"wait_after\":{},\"exit_code\":{},\"secondary_matches\":true,\"kernel_origin_proof\":false,\"socket_binding_proof\":false,\"no_direct_proof\":false}}",s.id.pid,s.id.created,s.before,s.after,s.exit);
            }
            println!("{{\"schema\":1,\"kind\":\"appid\",\"queries\":4,\"a_path_hex\":\"{}\",\"b_path_hex\":\"{}\",\"b_path_after_hex\":\"{}\",\"a_before\":\"{}\",\"b_before\":\"{}\",\"a_name_after_exit\":\"{}\",\"b_after\":\"{}\",\"opaque_bytes\":true,\"kernel_origin_proof\":false,\"socket_binding_proof\":false,\"no_direct_proof\":false}}",wide(&d.names[0]),wide(&d.names[1]),wide(&d.names[2]),hex(&d.apps[0]),hex(&d.apps[1]),hex(&d.apps[2]),hex(&d.apps[3]));
            println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"SAME_APPID_DISTINCT_PROCESSES_NOT_ALE_PROOF\",\"processes\":2,\"binding_mask\":{},\"appid_only_mask\":{},\"query_handle_rights\":1052672,\"pid_reuse_test_performed\":false,\"atomic_snapshot\":false,\"kernel_origin_proof\":false,\"socket_binding_proof\":false,\"no_direct_proof\":false}}",d.binding,d.weak);0
        }}
    }
    pub fn child(code:i32)->i32{
        let(tx,rx)=mpsc::sync_channel(1);
        let reader=std::thread::spawn(move||{let mut b=[0u8;1];let ok=io::stdin().read_exact(&mut b).is_ok()&&b==*b"G";let _=tx.send(ok);});
        match rx.recv_timeout(Duration::from_secs(45)){Ok(ok)=>{let _=reader.join();if ok{code}else{125}},Err(_)=>125}
    }
}
fn main(){
    let args:Vec<_>=std::env::args().skip(1).collect();
    if args==["--contract-matrix"]{if matrix(&mut io::stdout().lock()).is_err(){std::process::exit(2);}return;}
    #[cfg(all(windows,target_arch="x86_64",not(test)))]{
        if args.len()==2&&args[0]=="--child"{let code=match args[1].as_str(){"23"=>23,"29"=>29,_=>std::process::exit(2)};std::process::exit(win::child(code));}
        if args==["--own-siblings"]{std::process::exit(win::run());}
    }
    eprintln!("usage: --contract-matrix | --own-siblings (Windows x64 only)");std::process::exit(2);
}
#[cfg(test)]mod tests{
    use super::*;
    fn id()->Identity{Identity{pid:7,created:11}}
    fn live()->Sample{Sample{id:id(),before:258,after:258,exit:259}}
    #[test]fn exact_live_owner(){assert!(eligible(id(),live(),true));}
    #[test]fn same_appid_other_pid_denied(){let mut s=live();s.id.pid=8;assert!(!eligible(id(),s,true));}
    #[test]fn same_pid_other_epoch_denied(){let mut s=live();s.id.created=12;assert!(!eligible(id(),s,true));}
    #[test]fn equal_creation_different_pid_allowed_as_observation_not_owner(){let mut s=live();s.id.pid=8;assert_eq!(s.id.created,id().created);assert!(!eligible(id(),s,true));}
    #[test]fn zero_selected_pid_denied(){let mut e=id();e.pid=0;let mut s=live();s.id=e;assert!(!eligible(e,s,true));}
    #[test]fn zero_selected_epoch_denied(){let mut e=id();e.created=0;let mut s=live();s.id=e;assert!(!eligible(e,s,true));}
    #[test]fn empty_identity_denied(){let e=Identity{pid:0,created:0};let mut s=live();s.id=e;assert!(!eligible(e,s,true));}
    #[test]fn nonmatching_app_denied(){assert!(!eligible(id(),live(),false));}
    #[test]fn signaled_exit23_denied(){let mut s=live();s.before=0;s.after=0;s.exit=23;assert!(!eligible(id(),s,true));}
    #[test]fn signaled_exit259_denied(){let mut s=live();s.before=0;s.after=0;assert!(!eligible(id(),s,true));}
    #[test]fn exit_during_sample_denied(){let mut s=live();s.after=0;assert!(!eligible(id(),s,true));}
    #[test]fn inconsistent_wait_order_denied(){let mut s=live();s.before=0;assert!(!eligible(id(),s,true));}
    #[test]fn failed_wait_denied(){let mut s=live();s.before=u32::MAX;assert!(!eligible(id(),s,true));}
    #[test]fn wrong_exit_with_timeout_denied(){let mut s=live();s.exit=23;assert!(!eligible(id(),s,true));}
    #[test]fn abandoned_wait_denied(){let mut s=live();s.before=128;s.after=128;assert!(!eligible(id(),s,true));}
    #[test]fn appid_only_negative_witness(){let app_same=true;let mut s=live();s.id.pid=8;assert!(app_same&&!eligible(id(),s,app_same));}
    #[test]fn dead_origin_live_neighbor_not_replacement(){let mut dead=live();dead.before=0;dead.after=0;dead.exit=23;let mut neighbor=live();neighbor.id.pid=8;assert!(!eligible(id(),dead,true)&&!eligible(id(),neighbor,true));}
    #[test]fn large_creation_time_preserved(){let e=Identity{pid:7,created:u64::MAX};let mut s=live();s.id=e;assert!(eligible(e,s,true));}
    #[test]fn deterministic_matrix_cardinality(){let mut b=Vec::new();matrix(&mut b).unwrap();assert_eq!(String::from_utf8(b).unwrap().lines().count(),480);}
    #[test]fn deterministic_matrix_one_admission(){let mut b=Vec::new();matrix(&mut b).unwrap();assert_eq!(String::from_utf8(b).unwrap().lines().filter(|x|x.ends_with(":1")).count(),1);}
}
