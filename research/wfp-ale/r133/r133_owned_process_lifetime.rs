//! R133: query ONLY a child spawned from this very executable; no socket/WFP/driver.
//! An owned process handle is NOT an original-ALE-connection ownership proof.
//! Native/Win32 image NAMES are observations, not canonical file/section identity.
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
use std::io::{self, Write};
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const STILL_ACTIVE: u32 = 259;
const READ_RIGHTS: u32 = 0x0010_1000; // SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FileTime { low: u32, high: u32 }
impl FileTime { fn value(self) -> u64 { (u64::from(self.high) << 32) | u64::from(self.low) } }
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Seen { Exited, NotSignaled, RacedOrInconsistent, Unknown, QueryError }
fn observe(wait: u32, exit_ok: bool, code: u32) -> Seen {
    if !exit_ok { return Seen::QueryError; }
    match wait {
        WAIT_OBJECT_0 => Seen::Exited,
        WAIT_TIMEOUT if code == STILL_ACTIVE => Seen::NotSignaled,
        WAIT_TIMEOUT => Seen::RacedOrInconsistent,
        _ => Seen::Unknown,
    }
}
fn label(s: Seen) -> &'static str { match s {
    Seen::Exited => "EXITED", Seen::NotSignaled => "NOT_SIGNALED_AT_READ",
    Seen::RacedOrInconsistent => "RACED_OR_INCONSISTENT", Seen::Unknown => "UNKNOWN_WAIT",
    Seen::QueryError => "EXIT_QUERY_ERROR",
}}
fn units_hex(units: &[u16]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for unit in units { write!(&mut out,"{unit:04X}").expect("String formatting"); }
    out
}
fn matrix(out: &mut impl Write) -> io::Result<()> {
    for wait in [0u32,258,128,u32::MAX,1,999] {
        for code in [0u32,23,259,u32::MAX,1] { for ok in [false,true] {
            writeln!(out,"{wait}:{code}:{}:{}",u8::from(ok),label(observe(wait,ok,code)))?;
        }}
    } Ok(())
}
#[cfg(all(windows, target_arch="x86_64", not(test)))]
mod win {
    use super::*;
    use std::{ffi::c_void, os::windows::io::AsRawHandle,
        process::{Child, Command, Stdio}, sync::mpsc, time::Duration};
    use std::io::Read;
    type Handle = *mut c_void;
    #[link(name="kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access:u32, inherit:i32, pid:u32)->Handle;
        fn CloseHandle(handle:Handle)->i32;
        fn GetProcessId(handle:Handle)->u32;
        fn GetProcessTimes(handle:Handle,created:*mut FileTime,exited:*mut FileTime,
                           kernel:*mut FileTime,user:*mut FileTime)->i32;
        fn QueryFullProcessImageNameW(handle:Handle,flags:u32,name:*mut u16,len:*mut u32)->i32;
        fn GetExitCodeProcess(handle:Handle,code:*mut u32)->i32;
        fn WaitForSingleObject(handle:Handle,millis:u32)->u32;
        fn GetLastError()->u32;
    }
    #[derive(Debug)]
    struct Failure { stage:&'static str, code:u32 }
    type Result<T> = std::result::Result<T,Failure>;
    fn fail(stage:&'static str,code:u32)->Failure { Failure{stage,code} }
    fn last(stage:&'static str)->Failure { fail(stage,unsafe {GetLastError()}) }
    fn io_error(stage:&'static str,e:io::Error)->Failure {fail(stage,e.raw_os_error().unwrap_or(0) as u32)}
    // Secondary handle owns only query+wait rights. It is never inheritable.
    struct ReadHandle(Handle);
    impl ReadHandle {
        fn open_own_child(pid:u32)->Result<Self> {
            let h=unsafe{OpenProcess(READ_RIGHTS,0,pid)};
            if h.is_null(){Err(last("OpenProcess_own_child"))}else{Ok(Self(h))}
        }
        fn close(mut self)->Result<()> {
            let h=std::mem::replace(&mut self.0,std::ptr::null_mut());
            if unsafe{CloseHandle(h)}==0 {Err(last("CloseHandle"))}else{Ok(())}
        }
    }
    impl Drop for ReadHandle {
        fn drop(&mut self){if !self.0.is_null(){unsafe{let _=CloseHandle(self.0);}}}
    }
    // Any error drops the input pipe. The child then exits by itself on EOF;
    // it also has its own 30s deadline. No TerminateProcess or kill() here.
    struct OwnChild(Child);
    impl Drop for OwnChild {fn drop(&mut self){drop(self.0.stdin.take());}}
    fn pid(h:Handle)->Result<u32> {
        let n=unsafe{GetProcessId(h)};if n==0{Err(last("GetProcessId"))}else{Ok(n)}
    }
    fn times(h:Handle)->Result<(u64,u64)> {
        let(mut c,mut e,mut k,mut u)=(FileTime::default(),FileTime::default(),FileTime::default(),FileTime::default());
        if unsafe{GetProcessTimes(h,&mut c,&mut e,&mut k,&mut u)}==0{return Err(last("GetProcessTimes"));}
        Ok((c.value(),e.value())) // Exit time is USED only after a signaled wait.
    }
    fn image_name(h:Handle,flags:u32)->Result<Vec<u16>> {
        let mut name=vec![0u16;32768];let mut count=name.len() as u32;
        if unsafe{QueryFullProcessImageNameW(h,flags,name.as_mut_ptr(),&mut count)}==0 {
            return Err(last("QueryFullProcessImageNameW"));
        }
        if count==0 || count as usize>=name.len(){return Err(fail("image_name_length",count));}
        name.truncate(count as usize);Ok(name)
    }
    fn exit_code(h:Handle)->Result<u32> {
        let mut code=0;
        if unsafe{GetExitCodeProcess(h,&mut code)}==0 {Err(last("GetExitCodeProcess"))}else{Ok(code)}
    }
    fn wait(h:Handle,millis:u32)->Result<u32> {
        let status=unsafe{WaitForSingleObject(h,millis)};
        if status==u32::MAX{Err(last("WaitForSingleObject"))}else{Ok(status)}
    }
    struct Live { pid:u32,created:u64,win32:Vec<u16>,native:Vec<u16>,before:u32,after:u32,exit:u32 }
    fn live(h:Handle)->Result<Live> {
        let before=wait(h,0)?;let process_id=pid(h)?;
        let(created,_exit_undefined_while_alive)=times(h)?;
        let win32=image_name(h,0)?;let native=image_name(h,1)?;
        let code=exit_code(h)?;let after=wait(h,0)?;
        if before!=WAIT_TIMEOUT || after!=WAIT_TIMEOUT || created==0 ||
            observe(after,true,code)!=Seen::NotSignaled {
            return Err(fail("child_not_live_at_reads",after));
        }
        Ok(Live{pid:process_id,created,win32,native,before,after,exit:code})
    }
    struct Dead {pid:u32,created:u64,exited:u64,wait:u32,code:u32}
    fn dead(h:Handle)->Result<Dead> {
        let state=wait(h,0)?;
        if state!=WAIT_OBJECT_0{return Err(fail("child_not_signaled",state));}
        let process_id=pid(h)?;let(created,exited)=times(h)?;let code=exit_code(h)?;
        if observe(state,true,code)!=Seen::Exited || exited==0 {return Err(fail("exit_not_observed",code));}
        Ok(Dead{pid:process_id,created,exited,wait:state,code})
    }
    struct Case {wanted:u32,live:Live,dead:Dead}
    fn case(wanted:u32)->Result<Case> {
        let exe=std::env::current_exe().map_err(|e|io_error("current_exe",e))?;
        // Target cannot be supplied by the caller: only this verified executable.
        let mut child=OwnChild(Command::new(exe).arg("--child").arg(wanted.to_string())
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().map_err(|e|io_error("spawn_own_child",e))?);
        let expected_pid=child.0.id();let primary=child.0.as_raw_handle();
        // The CreateProcess-derived handle is already held, before PID lookup.
        let secondary=ReadHandle::open_own_child(expected_pid)?;
        let a=live(primary)?;let b=live(secondary.0)?;
        if a.pid!=expected_pid || b.pid!=expected_pid || a.created!=b.created ||
            a.win32!=b.win32 || a.native!=b.native {return Err(fail("live_identity_mismatch",0));}
        let mut input=child.0.stdin.take().ok_or_else(||fail("child_stdin_missing",0))?;
        input.write_all(b"G").map_err(|e|io_error("release_own_child",e))?;drop(input);
        let completed=wait(primary,10000)?;
        if completed!=WAIT_OBJECT_0 {return Err(fail("child_exit_timeout",completed));}
        // The SAME two retained handles are read after normal self-exit.
        let da=dead(primary)?;let db=dead(secondary.0)?;
        if da.pid!=a.pid || db.pid!=a.pid || da.created!=a.created || db.created!=a.created ||
            da.exited!=db.exited || da.code!=wanted || db.code!=wanted {
            return Err(fail("retained_identity_or_exit_mismatch",0));
        }
        // try_wait does not introduce an unbounded wait, even with exit code 259.
        let status=child.0.try_wait().map_err(|e|io_error("child_try_wait",e))?
            .ok_or_else(||fail("child_status_missing",0))?;
        if status.code()!=Some(wanted as i32){return Err(fail("rust_exit_status_mismatch",0));}
        secondary.close()?;
        Ok(Case{wanted,live:a,dead:da})
    }
    pub fn child_main(wanted:u32)->i32 {
        let(tx,rx)=mpsc::sync_channel(1);
        let reader=std::thread::spawn(move||{
            let mut byte=[0u8;1];
            let ok=io::stdin().read_exact(&mut byte).is_ok() && byte==*b"G";
            let _=tx.send(ok);
        });
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(ok)=>{let _=reader.join();if ok{wanted as i32}else{125}},
            Err(_)=>125, // Only this helper exits; never kills the parent or another process.
        }
    }
    pub fn run()->i32 {
        let result=(||->Result<Vec<Case>>{Ok(vec![case(23)?,case(259)?])})();
        match result {
            Err(e)=>{println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"PROBE_ERROR\",\"stage\":\"{}\",\"code\":{},\"code_hex\":\"0x{:08X}\",\"kernel_origin_proof\":false,\"network_owner_proof\":false,\"no_direct_proof\":false}}",e.stage,e.code,e.code);2},
            Ok(cases)=>{
                // All child/secondary handles have left their scopes before output.
                for (i,c) in cases.iter().enumerate(){
                    println!("{{\"schema\":1,\"kind\":\"alive\",\"case\":{i},\"planned_exit\":{},\"pid\":{},\"creation_filetime_hex\":\"{:016X}\",\"wait_before\":{},\"wait_after\":{},\"get_exit_code\":{},\"secondary_matches\":true,\"win32_name_utf16_hex\":\"{}\",\"native_name_utf16_hex\":\"{}\",\"kernel_origin_proof\":false,\"network_owner_proof\":false,\"no_direct_proof\":false}}",
                        c.wanted,c.live.pid,c.live.created,c.live.before,c.live.after,c.live.exit,units_hex(&c.live.win32),units_hex(&c.live.native));
                    println!("{{\"schema\":1,\"kind\":\"exited\",\"case\":{i},\"planned_exit\":{},\"pid\":{},\"creation_filetime_hex\":\"{:016X}\",\"exit_filetime_hex\":\"{:016X}\",\"wait_result\":{},\"get_exit_code\":{},\"secondary_matches\":true,\"same_held_handles\":true,\"kernel_origin_proof\":false,\"network_owner_proof\":false,\"no_direct_proof\":false}}",
                        c.wanted,c.dead.pid,c.dead.created,c.dead.exited,c.dead.wait,c.dead.code);
                }
                println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"OWN_CHILD_HANDLE_LIFETIME_PASS_NOT_NETWORK_PROOF\",\"cases\":2,\"readonly_open_rights\":{READ_RIGHTS},\"exit259_is_signaled\":true,\"pid_reuse_test_performed\":false,\"canonical_file_identity_proof\":false,\"atomic_snapshot\":false,\"kernel_origin_proof\":false,\"network_owner_proof\":false,\"no_direct_proof\":false}}");0
            }
        }
    }
}
fn main(){
    let args:Vec<String>=std::env::args().skip(1).collect();
    if args==["--gate-matrix"] {
        if matrix(&mut io::stdout().lock()).is_err(){std::process::exit(2);}return;
    }
    #[cfg(all(windows,target_arch="x86_64",not(test)))]
    {
        if args.len()==2 && args[0]=="--child" {
            let wanted=match args[1].as_str(){"23"=>23,"259"=>259,_=>std::process::exit(2)};
            std::process::exit(win::child_main(wanted));
        }
        if args==["--own-child-probe"]{std::process::exit(win::run());}
    }
    eprintln!("usage: --gate-matrix | --own-child-probe (Windows x86_64 only)");
    std::process::exit(2);
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn wait_signaled_zero_exit(){assert_eq!(observe(0,true,0),Seen::Exited);}
    #[test] fn wait_signaled_exit23(){assert_eq!(observe(0,true,23),Seen::Exited);}
    #[test] fn wait_signaled_exit259_is_dead(){assert_eq!(observe(0,true,259),Seen::Exited);}
    #[test] fn timeout_plus_active_is_observation(){assert_eq!(observe(258,true,259),Seen::NotSignaled);}
    #[test] fn timeout_plus_other_is_race_not_alive(){assert_eq!(observe(258,true,23),Seen::RacedOrInconsistent);}
    #[test] fn failed_wait_not_alive(){assert_eq!(observe(u32::MAX,true,259),Seen::Unknown);}
    #[test] fn abandoned_not_a_process_signal(){assert_eq!(observe(128,true,259),Seen::Unknown);}
    #[test] fn exit_query_failure_not_promoted(){for w in [0,258,u32::MAX]{assert_eq!(observe(w,false,259),Seen::QueryError);}}
    #[test] fn unexpected_wait_not_promoted(){assert_eq!(observe(999,true,259),Seen::Unknown);}
    #[test] fn all_application_exit_codes_can_be_terminal(){for c in [0,23,259,u32::MAX]{assert_eq!(observe(0,true,c),Seen::Exited);}}
    #[test] fn filetime_abi(){assert_eq!(std::mem::size_of::<FileTime>(),8);assert_eq!(std::mem::align_of::<FileTime>(),4);}
    #[test] fn filetime_assembly_no_json_precision_loss(){assert_eq!(FileTime{low:0x89abcdef,high:0x01234567}.value(),0x0123456789abcdef);}
    #[test] fn utf16_hex_is_lossless_including_surrogates(){assert_eq!(units_hex(&[0x41,0x5c,0xd800,0]),"0041005CD8000000");}
    #[test] fn rights_do_not_include_terminate_vm_or_write(){assert_eq!(READ_RIGHTS,0x00101000);assert_eq!(READ_RIGHTS & (1|2|8|16|32),0);}
    #[test] fn naive_exit_only_rule_has_counterexample(){assert_eq!(259,STILL_ACTIVE);assert_ne!(observe(0,true,259),Seen::NotSignaled);}
    #[test] fn matrix_cardinality(){let mut b=Vec::new();matrix(&mut b).unwrap();assert_eq!(String::from_utf8(b).unwrap().lines().count(),60);}
}
