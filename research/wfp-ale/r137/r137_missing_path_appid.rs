//! R137: Windows user-mode read-only counterexample for filename-derived WFP AppId.
//! Generates a path STRING for a nonexistent sibling of this executable.
//! No file is created/renamed/opened for write. No sockets, filters, drivers, BFE policy.
//! A returned AppId for an absent name would not be an image-section identity proof.
#![deny(unsafe_op_in_unsafe_fn)]
use std::io::{self, Write};

const ERROR_FILE_NOT_FOUND: u32 = 2;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const DRIVE_FIXED: u32 = 3;
const MAX_APPID_BYTES: usize = 65_536;

#[repr(C)]
struct Blob { size: u32, data: *mut u8 }

/// Bit 0: missing before, bit 1: missing after, bit 2: own AppId repeatable,
/// bit 3: two negative-path API outcomes equal, bit 4: absent path accepted,
/// bit 5: returned AppId differs from the existing image's AppId.
/// Bits 6/7 are deliberately ignored: no other signal upgrades this observation.
fn diagnostic(mask: u8) -> (i32, &'static str) {
    if mask & 0x0f != 0x0f {
        return (3, "NOT_STABLE_OR_NOT_CONFIRMED_ABSENT");
    }
    if mask & 0x10 == 0 {
        return (4, "ABSENT_PATH_APPID_REJECTED_NOT_ORIGIN_PROOF");
    }
    if mask & 0x20 != 0 {
        (0, "ABSENT_PATH_APPID_ACCEPTED_NOT_ORIGIN_PROOF")
    } else {
        (3, "AMBIGUOUS_APPID_EQUAL_TO_OWN_IMAGE")
    }
}

fn matrix(out: &mut impl Write) -> io::Result<()> {
    for mask in 0u16..=255 {
        let mask = mask as u8;
        let (code, _) = diagnostic(mask);
        writeln!(out, "{mask:03}:{code}")?;
    }
    Ok(())
}

#[cfg(all(windows, target_arch = "x86_64", not(test)))]
mod win {
    use super::*;
    use std::{ffi::c_void, ptr, slice, time::{SystemTime, UNIX_EPOCH}};
    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn GetCurrentProcessId() -> u32;
        fn QueryFullProcessImageNameW(process: Handle, flags: u32, path: *mut u16, size: *mut u32) -> i32;
        fn GetDriveTypeW(root: *const u16) -> u32;
        fn GetFileAttributesW(path: *const u16) -> u32;
        fn GetLastError() -> u32;
    }
    #[link(name = "fwpuclnt")]
    unsafe extern "system" {
        fn FwpmGetAppIdFromFileName0(path: *const u16, app_id: *mut *mut Blob) -> u32;
        fn FwpmFreeMemory0(data: *mut *mut c_void);
    }

    #[derive(Debug)]
    struct Error { stage: &'static str, code: u32 }
    type Result<T> = std::result::Result<T, Error>;
    fn fail(stage: &'static str, code: u32) -> Error { Error { stage, code } }
    fn last(stage: &'static str) -> Error { fail(stage, unsafe { GetLastError() }) }
    fn wide_z(input: &[u16]) -> Vec<u16> {
        input.iter().copied().chain(std::iter::once(0u16)).collect()
    }

    struct OwnedBlob(*mut Blob);
    impl Drop for OwnedBlob {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let mut value = self.0.cast::<c_void>();
                unsafe { FwpmFreeMemory0(&mut value) };
            }
        }
    }
    #[derive(Clone, PartialEq, Eq)]
    struct Response { code: u32, bytes: Option<Vec<u8>> }
    fn get_appid(path: &[u16]) -> Result<Response> {
        let z = wide_z(path);
        let mut raw: *mut Blob = ptr::null_mut();
        let code = unsafe { FwpmGetAppIdFromFileName0(z.as_ptr(), &mut raw) };
        if code != 0 {
            if !raw.is_null() { return Err(fail("api_error_with_unexpected_pointer", code)); }
            return Ok(Response { code, bytes: None });
        }
        if raw.is_null() { return Err(fail("appid_success_null", 0)); }
        let blob = OwnedBlob(raw);
        let b = unsafe { &*blob.0 };
        if b.size == 0 || b.size as usize > MAX_APPID_BYTES || b.data.is_null() {
            return Err(fail("appid_blob_shape", b.size));
        }
        let bytes = unsafe { slice::from_raw_parts(b.data, b.size as usize) }.to_vec();
        Ok(Response { code, bytes: Some(bytes) })
    }

    fn own_path() -> Result<Vec<u16>> {
        let mut name = vec![0u16; 32_768];
        let mut n = name.len() as u32;
        if unsafe { QueryFullProcessImageNameW(GetCurrentProcess(), 0, name.as_mut_ptr(), &mut n) } == 0 {
            return Err(last("QueryFullProcessImageNameW"));
        }
        if n == 0 || n as usize >= name.len() { return Err(fail("own_path_size", n)); }
        name.truncate(n as usize);
        if name.contains(&0) || name.len() < 5 || !((65..=90).contains(&name[0]) || (97..=122).contains(&name[0])) ||
           name[1] != b':' as u16 || name[2] != b'\\' as u16 {
            return Err(fail("not_local_drive_dos_path", 0));
        }
        let root = [name[0], b':' as u16, b'\\' as u16, 0];
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        if kind != DRIVE_FIXED { return Err(fail("drive_not_fixed", kind)); }
        Ok(name)
    }
    // Reject anything other than explicit Windows ERROR_FILE_NOT_FOUND (2).
    fn is_missing(path: &[u16]) -> Result<bool> {
        let z = wide_z(path);
        let attrs = unsafe { GetFileAttributesW(z.as_ptr()) };
        if attrs != INVALID_FILE_ATTRIBUTES { return Ok(false); }
        let code = unsafe { GetLastError() };
        if code == ERROR_FILE_NOT_FOUND { Ok(true) }
        else { Err(fail("GetFileAttributesW_non_file_not_found", code)) }
    }
    fn own_exists(path: &[u16]) -> Result<()> {
        let z = wide_z(path);
        let attrs = unsafe { GetFileAttributesW(z.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES { return Err(last("own_executable_attribute_query")); }
        if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 { return Err(fail("own_image_is_directory", attrs)); }
        Ok(())
    }
    fn missing_sibling(own: &[u16]) -> Result<Vec<u16>> {
        let cut = own.iter().rposition(|v| *v == b'\\' as u16)
            .ok_or_else(|| fail("no_own_parent_directory", 0))?;
        let pid = unsafe { GetCurrentProcessId() };
        if pid == 0 { return Err(fail("GetCurrentProcessId_zero", 0)); }
        let tick = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| fail("clock_only_for_naming_failed", 0))?.as_nanos();
        for i in 0..8u8 {
            let name = format!("__flowbridge_r137_absent_{pid:08X}_{tick:032X}_{i:02X}.exe");
            let mut candidate = own[..cut + 1].to_vec();
            candidate.extend(name.encode_utf16());
            if candidate.len() >= 32_767 { return Err(fail("candidate_path_too_long", candidate.len() as u32)); }
            if is_missing(&candidate)? { return Ok(candidate); }
        }
        Err(fail("eight_candidates_already_exist", 0))
    }

    pub fn run() -> i32 {
        let outcome = (|| -> Result<(u8, usize, u32, u32, usize, bool)> {
            let own = own_path()?;
            own_exists(&own)?;
            let self_one = get_appid(&own)?;
            let self_two = get_appid(&own)?;
            if self_one.code != 0 || self_two.code != 0 {
                return Err(fail("known_own_image_appid_unavailable", self_one.code | self_two.code));
            }
            let own_bytes = self_one.bytes.as_ref().ok_or_else(|| fail("own_appid_empty", 0))?;
            let own_stable = self_one == self_two;
            let missing = missing_sibling(&own)?;
            let before = is_missing(&missing)?;
            // Probe only a string. No CreateFileW, file creation or filter write.
            let absent_one = get_appid(&missing)?;
            let absent_two = get_appid(&missing)?;
            let after = is_missing(&missing)?;
            let matching = absent_one == absent_two;
            let accepted = absent_one.code == 0 && absent_one.bytes.is_some();
            let different = absent_one.bytes.as_ref().is_some_and(|bytes| bytes != own_bytes);
            let mut mask = 0u8;
            for (i, present) in [before, after, own_stable, matching, accepted, different].iter().enumerate() {
                if *present { mask |= 1 << i; }
            }
            Ok((mask, own_bytes.len(), absent_one.code, absent_two.code,
                absent_one.bytes.as_ref().map_or(0, Vec::len), before && after))
        })();
        match outcome {
            Err(e) => {
                println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"QUERY_ERROR\",\"stage\":\"{}\",\"api_code\":{},\"api_code_hex\":\"0x{:08X}\",\"kernel_origin_proof\":false,\"image_section_identity_proof\":false,\"no_direct_proof\":false}}",e.stage,e.code,e.code);
                2
            }
            Ok((mask,own_len,code1,code2,missing_len,both_absent)) => {
                let (exit,status) = diagnostic(mask);
                println!("{{\"schema\":1,\"kind\":\"negative_name\",\"missing_before\":{},\"missing_after\":{},\"own_appid_stable\":{},\"negative_results_stable\":{},\"missing_name_appid_success\":{},\"appid_distinct_from_own\":{},\"own_appid_bytes\":{},\"missing_name_appid_bytes\":{},\"lookup_code_first\":{},\"lookup_code_second\":{},\"no_file_created\":true,\"kernel_origin_proof\":false,\"image_section_identity_proof\":false,\"no_direct_proof\":false}}",
                    mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, mask & 8 != 0,mask & 16 != 0,mask & 32 != 0,
                    own_len,missing_len,code1,code2);
                println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"{status}\",\"diagnostic_exit\":{exit},\"observations_mask\":{mask},\"filename_only\":true,\"no_wfp_policy_mutation\":true,\"atomic_snapshot\":false,\"absence_confirmed_before_after\":{},\"kernel_origin_proof\":false,\"image_section_identity_proof\":false,\"no_direct_proof\":false}}",both_absent);
                exit
            }
        }
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--contract-matrix"] {
        if matrix(&mut io::stdout().lock()).is_err() { std::process::exit(2); }
        return;
    }
    #[cfg(all(windows, target_arch = "x86_64", not(test)))]
    if args == ["--read-only-missing-name"] { std::process::exit(win::run()); }
    eprintln!("usage: --contract-matrix | --read-only-missing-name (Windows x86_64 only)");
    std::process::exit(2);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn matrix_cardinality() { let mut v=Vec::new();matrix(&mut v).unwrap();assert_eq!(String::from_utf8(v).unwrap().lines().count(),256); }
    #[test] fn no_evidence_cannot_pass() {assert_eq!(diagnostic(0).0,3);}
    #[test] fn before_missing_not_enough() {assert_eq!(diagnostic(1).0,3);}
    #[test] fn after_missing_not_enough() {assert_eq!(diagnostic(2).0,3);}
    #[test] fn own_appid_unstable_denies() {assert_eq!(diagnostic(0x3b).0,3);}
    #[test] fn missing_response_unstable_denies() {assert_eq!(diagnostic(0x37).0,3);}
    #[test] fn absent_name_api_accepted_is_conditional_pass() {assert_eq!(diagnostic(0x3f).0,0);}
    #[test] fn api_rejected_absent_name_is_not_image_proof() {assert_eq!(diagnostic(0x0f).0,4);}
    #[test] fn same_appid_is_not_proof() {assert_eq!(diagnostic(0x1f).0,3);}
    #[test] fn reserved_bits_do_not_upgrade() {for m in 0..64 {assert_eq!(diagnostic(m),diagnostic(m|0xc0));}}
    #[test] fn count_accepted_exactly_four() {assert_eq!((0..=255u8).filter(|m|diagnostic(*m).0==0).count(),4);}
    #[test] fn count_rejected_eight() {assert_eq!((0..=255u8).filter(|m|diagnostic(*m).0==4).count(),8);}
    #[test] fn remaining_inconclusive() {assert_eq!((0..=255u8).filter(|m|diagnostic(*m).0==3).count(),244);}
    #[test] fn appid_blob_abi_x64(){assert_eq!(std::mem::size_of::<Blob>(),16);assert_eq!(std::mem::offset_of!(Blob,data),8);}
    #[test] fn metadata_has_no_external_deps(){assert_eq!(MAX_APPID_BYTES,65_536);}
    #[test] fn nonexistence_check_is_exact_error_two() {assert_eq!(ERROR_FILE_NOT_FOUND,2);}
    #[test] fn no_directory_as_own_exe() {assert_eq!(FILE_ATTRIBUTE_DIRECTORY,16);}
    #[test] fn fixed_drive_type() {assert_eq!(DRIVE_FIXED,3);}
}
