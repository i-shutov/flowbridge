//! R72 user-mode Windows-only observational probe (not a driver and not a proof
//! of historic ALE origin). No dependencies, network connections, filters,
//! privileged changes, writes to OS configuration, or socket operations.
//! Build later on an authorized Windows workstation:
//!   rustc --edition=2021 r72_win_process_readonly.rs -o r72_probe.exe
//!   .\r72_probe.exe [PID]
//! The probe has NOT been run on Windows in this research cycle.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod win {
    use std::{ffi::c_void, io, ptr};
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const NAME_CAP: usize = 32768;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime { low: u32, high: u32 }
    impl FileTime { fn ticks(self)->u64 { ((self.high as u64)<<32) | self.low as u64 } }
    #[repr(C)]
    struct FwpByteBlob { size: u32, data: *mut u8 }

    #[link(name="kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcessId()->u32;
        fn OpenProcess(rights:u32, inherit:i32, pid:u32)->*mut c_void;
        fn CloseHandle(handle:*mut c_void)->i32;
        fn GetProcessTimes(handle:*mut c_void, creation:*mut FileTime, exit:*mut FileTime,
                           kernel:*mut FileTime, user:*mut FileTime)->i32;
        fn QueryFullProcessImageNameW(handle:*mut c_void, flags:u32,
                                      buffer:*mut u16, length:*mut u32)->i32;
    }
    #[link(name="fwpuclnt")]
    unsafe extern "system" {
        fn FwpmGetAppIdFromFileName0(path:*const u16, id:*mut *mut FwpByteBlob)->u32;
        fn FwpmFreeMemory0(memory:*mut *mut c_void);
    }
    struct Handle(*mut c_void);
    impl Drop for Handle {fn drop(&mut self){if !self.0.is_null(){unsafe{CloseHandle(self.0)};}}}
    struct FwpOwned(*mut FwpByteBlob);
    impl Drop for FwpOwned {fn drop(&mut self){if !self.0.is_null(){let mut p=self.0.cast::<c_void>();unsafe{FwpmFreeMemory0(&mut p)};}}}

    pub fn run()->io::Result<()> {
        let args:Vec<String>=std::env::args().collect();
        if args.len()>2{return Err(io::Error::other("usage: r72_probe.exe [PID]"));}
        let pid=if args.len()==2{args[1].parse::<u32>().map_err(|_|io::Error::other("invalid pid"))?}
                else{unsafe{GetCurrentProcessId()}};
        if pid==0{return Err(io::Error::other("invalid pid"));}
        // Minimal query-only privilege; never enable SeDebugPrivilege.
        let handle=Handle(unsafe{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid)});
        if handle.0.is_null(){return Err(io::Error::last_os_error());}
        let mut creation=FileTime::default();let mut exit=FileTime::default();
        let mut kernel=FileTime::default();let mut user=FileTime::default();
        if unsafe{GetProcessTimes(handle.0,&mut creation,&mut exit,&mut kernel,&mut user)}==0{
            return Err(io::Error::last_os_error());
        }
        let mut chars=vec![0u16;NAME_CAP];let mut n=chars.len() as u32;
        if unsafe{QueryFullProcessImageNameW(handle.0,0,chars.as_mut_ptr(),&mut n)}==0{
            return Err(io::Error::last_os_error());
        }
        if n==0||n as usize>=chars.len(){return Err(io::Error::other("image path length"));}
        let path=String::from_utf16(&chars[..n as usize])
            .map_err(|_|io::Error::other("image utf16"))?;
        // WFP AppId is path-derived; it is not a cryptographic EXE/image-section
        // identity and does not link this process to a historic ALE endpoint.
        let wide:Vec<u16>=path.encode_utf16().chain(Some(0)).collect();
        let mut blob=ptr::null_mut();
        let status=unsafe{FwpmGetAppIdFromFileName0(wide.as_ptr(),&mut blob)};
        let owned=FwpOwned(blob);
        if status!=0{return Err(io::Error::other(format!("FwpmGetAppIdFromFileName0 failed: {status}")));}
        if owned.0.is_null(){return Err(io::Error::other("null appid"));}
        let b=unsafe{&*owned.0};
        if b.size<4||b.size>65536||b.size%2!=0||b.data.is_null(){return Err(io::Error::other("invalid appid blob"));}
        let raw=unsafe{std::slice::from_raw_parts(b.data,b.size as usize)};
        println!("pid={pid}");
        println!("creation_100ns_since_1601={}",creation.ticks());
        println!("win32_process_image={path:?}");
        println!("wfp_appid_blob_hex={}", raw.iter().map(|x|format!("{x:02x}")).collect::<String>());
        println!("proof_of_original_ale_owner=false");
        println!("proof_of_accepted_socket=false");
        println!("proof_of_no_direct=false");
        Ok(())
    }
}

#[cfg(windows)]
fn main(){if let Err(e)=win::run(){eprintln!("read_only_probe_failed: {e}");std::process::exit(1)}}
#[cfg(not(windows))]
fn main(){eprintln!("Windows-only read-only probe. Not an ALE-origin proof.");std::process::exit(2)}
