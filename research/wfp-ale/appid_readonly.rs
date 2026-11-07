//! Read-only Windows WFP AppId comparison for two explicit executable paths.
//!
//! Native user-mode FwpmGetAppIdFromFileName0 only. No BFE session,
//! filter registration, driver, sockets, service, or policy mutation.
//! Equal/unequal blobs are NOT proof of a live connection's owner.

#[cfg(windows)]
mod windows_probe {
    use std::env;
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    #[repr(C)]
    struct FwpByteBlob {
        size: u32,
        data: *mut u8,
    }

    #[link(name = "Fwpuclnt")]
    unsafe extern "system" {
        fn FwpmGetAppIdFromFileName0(file_name: *const u16, app_id: *mut *mut FwpByteBlob) -> u32;
        fn FwpmFreeMemory0(pointer: *mut *mut c_void);
    }

    struct OwnedAppId(*mut FwpByteBlob);

    impl Drop for OwnedAppId {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let mut raw: *mut c_void = self.0.cast();
                // FwpmFreeMemory0 must release allocations made by Fwpm* APIs.
                unsafe { FwpmFreeMemory0(&mut raw) };
                self.0 = std::ptr::null_mut();
            }
        }
    }

    fn app_id(path: &OsStr) -> Result<Vec<u8>, String> {
        let p = Path::new(path);
        if !p.is_absolute() || !p.is_file() {
            return Err("requires an existing absolute local executable file".into());
        }
        let mut wide: Vec<u16> = path.encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) || wide.len() >= 32767 {
            return Err("invalid Windows executable path".into());
        }
        wide.push(0);
        let mut raw: *mut FwpByteBlob = std::ptr::null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut raw) };
        let owned = OwnedAppId(raw);
        if status != 0 {
            return Err(format!("FwpmGetAppIdFromFileName0 returned 0x{status:08x}"));
        }
        if owned.0.is_null() {
            return Err("WFP reported success with a null AppId".into());
        }
        let blob = unsafe { &*owned.0 };
        if blob.size == 0 || blob.size > 65536 || blob.data.is_null() {
            return Err("WFP returned an empty or invalid AppId blob".into());
        }
        let bytes = unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) };
        Ok(bytes.to_vec())
    }

    pub fn run() -> Result<(), String> {
        let paths: Vec<_> = env::args_os().skip(1).collect();
        if paths.len() != 2 {
            return Err("usage: appid_readonly.exe <absolute A.exe> <absolute B.exe>".into());
        }
        let a = app_id(&paths[0])?;
        let b = app_id(&paths[1])?;
        // Avoid printing raw AppId (which may encode paths) or executable names.
        println!(
            "{{\"read_only\":true,\"app_ids_equal\":{},\"a_bytes\":{},\"b_bytes\":{},\"kernel_owner_proved\":false}}",
            a == b,
            a.len(),
            b.len()
        );
        Ok(())
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_probe::run() {
        eprintln!("read-only WFP AppId probe failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("read-only WFP AppId probe requires Windows and Fwpuclnt.dll");
    std::process::exit(2);
}
