//! R129: four exact BFE GETs, no enumeration, mutation, driver or socket.
//! Returned presence is an observation at each call, NEVER enforcement proof.
#![deny(unsafe_op_in_unsafe_fn)]
use std::io::{self, Write};

const NOT_FOUND: u32 = 0x8032_0003; // FWP_E_FILTER_NOT_FOUND, not generic NOT_FOUND.
const ACCESS_DENIED: u32 = 5;      // ERROR_ACCESS_DENIED, raw DWORD from the API.
const LABELS: [&str; 4] = ["auth_connect_v4", "auth_connect_v6", "connect_redirect_v4", "connect_redirect_v6"];
const KEYS: [&str; 4] = [
    "1649f030-25b3-4e01-9ca1-5ca803010019", "1649f031-25b3-4e01-9ca1-5ca803010019",
    "1649f032-25b3-4e01-9ca1-5ca803010019", "1649f033-25b3-4e01-9ca1-5ca803010019",
];
#[repr(C)]
#[derive(Clone, Copy)]
struct Guid { d1: u32, d2: u16, d3: u16, d4: [u8; 8] }
fn key(i: usize) -> Guid {
    Guid { d1: 0x1649f030 + i as u32, d2: 0x25b3, d3: 0x4e01,
           d4: [0x9c,0xa1,0x5c,0xa8,0x03,0x01,0x00,0x19] }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation { Present, Missing, Denied, Error, Invalid }
impl Observation {
    fn name(self) -> &'static str { match self {
        Self::Present => "FOUND_BY_KEY", Self::Missing => "NOT_FOUND_RETURNED",
        Self::Denied => "ACCESS_DENIED_RETURNED", Self::Error => "OTHER_API_ERROR",
        Self::Invalid => "INVALID_API_RESULT",
    }}
}
fn observe(code: u32, pointer_present: bool) -> Observation {
    match (code, pointer_present) {
        (0, true) => Observation::Present,
        (0, false) => Observation::Invalid,
        (_, true) => Observation::Invalid, // No ownership/free inferred on an error.
        (NOT_FOUND, false) => Observation::Missing,
        (ACCESS_DENIED, false) => Observation::Denied,
        _ => Observation::Error,
    }
}
fn finish(rows: &[Observation; 4], close: u32) -> (i32, &'static str) {
    if close != 0 || rows.iter().any(|r| matches!(r, Observation::Error | Observation::Invalid)) {
        (2, "QUERY_OR_CLOSE_ERROR")
    } else if rows.contains(&Observation::Denied) {
        (5, "ACCESS_DENIED_OBSERVED")
    } else if rows.contains(&Observation::Missing) {
        (4, "NOT_FOUND_OBSERVED")
    } else { (3, "ALL_FOUR_GETS_SUCCEEDED_NOT_PROOF") }
}
fn matrix(out: &mut impl Write) -> io::Result<()> {
    let states = [Observation::Present, Observation::Missing, Observation::Denied,
                  Observation::Error, Observation::Invalid];
    for a in 0..5 { for b in 0..5 { for c in 0..5 { for d in 0..5 { for close in 0..2 {
        let rows = [states[a], states[b], states[c], states[d]];
        let (exit, _) = finish(&rows, close);
        writeln!(out, "{a}{b}{c}{d}:{close}:{exit}")?;
    }}}}}
    Ok(())
}
#[cfg(all(windows, target_arch = "x86_64", not(test)))]
mod win {
    use super::*;
    use std::{ffi::c_void, ptr};
    #[link(name = "fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineOpen0(server: *const u16, authn: u32, identity: *const c_void,
                          session: *const c_void, engine: *mut *mut c_void) -> u32;
        fn FwpmFilterGetByKey0(engine: *mut c_void, key: *const Guid,
                               output: *mut *mut c_void) -> u32;
        fn FwpmFreeMemory0(output: *mut *mut c_void);
        fn FwpmEngineClose0(engine: *mut c_void) -> u32;
    }
    // FWPM_FILTER0 stays opaque. No prefix/union/condition pointer dereference.
    struct Engine(*mut c_void);
    impl Engine {
        fn close(mut self) -> u32 {
            let handle = std::mem::replace(&mut self.0, ptr::null_mut());
            unsafe { FwpmEngineClose0(handle) }
        }
    }
    impl Drop for Engine {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { let _ = FwpmEngineClose0(self.0); } }
        }
    }
    pub fn run() -> i32 {
        let mut h = ptr::null_mut();
        let open = unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut h) };
        if open != 0 || h.is_null() {
            // Failure output is not treated as an owned engine handle.
            println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"OPEN_ERROR\",\"api_code\":{open},\"api_code_hex\":\"0x{open:08X}\",\"diagnostic_exit\":2,\"kernel_proof\":false,\"no_direct_proof\":false,\"atomic_snapshot\":false}}");
            return 2;
        }
        let engine = Engine(h);
        let mut rows = [Observation::Error; 4];
        // Store results until AFTER engine close: no stdout stall holds a session.
        let mut codes = [0u32; 4];
        let mut pointers = [false; 4];
        for i in 0..4 {
            let mut raw = ptr::null_mut();
            let code = unsafe { FwpmFilterGetByKey0(engine.0, &key(i), &mut raw) };
            codes[i] = code;
            pointers[i] = !raw.is_null();
            rows[i] = observe(code, pointers[i]);
            if code == 0 && !raw.is_null() { unsafe { FwpmFreeMemory0(&mut raw); } }
        }
        let close = engine.close();
        let (exit, status) = finish(&rows, close);
        for i in 0..4 {
            println!("{{\"schema\":1,\"kind\":\"filter\",\"rule\":\"{}\",\"key\":\"{}\",\"api_code\":{},\"api_code_hex\":\"0x{:08X}\",\"pointer_present\":{},\"observation\":\"{}\",\"kernel_proof\":false,\"no_direct_proof\":false}}", LABELS[i], KEYS[i], codes[i], codes[i], pointers[i], rows[i].name());
        }
        println!("{{\"schema\":1,\"kind\":\"summary\",\"status\":\"{status}\",\"queries\":4,\"close_code\":{close},\"close_code_hex\":\"0x{close:08X}\",\"diagnostic_exit\":{exit},\"kernel_proof\":false,\"no_direct_proof\":false,\"atomic_snapshot\":false}}");
        exit // No live-BFE result exits zero; even four FOUNDs are not a safety PASS.
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--contract-matrix"] {
        if matrix(&mut io::stdout().lock()).is_err() { std::process::exit(2); }
        return;
    }
    if args != ["--read-only-bfe"] {
        eprintln!("usage: r129_filter_get_by_key.exe --read-only-bfe | --contract-matrix");
        std::process::exit(2);
    }
    #[cfg(all(windows, target_arch = "x86_64", not(test)))]
    std::process::exit(win::run());
    #[cfg(not(all(windows, target_arch = "x86_64", not(test))))]
    { eprintln!("Live probe requires Windows x86_64; no API called"); std::process::exit(2); }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn found_requires_success_and_pointer() { assert_eq!(observe(0,true),Observation::Present); }
    #[test] fn success_null_is_not_missing() { assert_eq!(observe(0,false),Observation::Invalid); }
    #[test] fn missing_is_exact_fwp_error() { assert_eq!(observe(NOT_FOUND,false),Observation::Missing); }
    #[test] fn denied_is_not_missing() { assert_eq!(observe(5,false),Observation::Denied); }
    #[test] fn generic_not_found_is_not_filter_not_found() { assert_eq!(observe(0x80320008,false),Observation::Error); }
    #[test] fn rpc_failure_is_unknown() { assert_eq!(observe(1722,false),Observation::Error); }
    #[test] fn unexpected_pointer_is_invalid() { for c in [5,NOT_FOUND,1722,u32::MAX] { assert_eq!(observe(c,true),Observation::Invalid); } }
    #[test] fn all_found_is_not_zero() { assert_eq!(finish(&[Observation::Present;4],0).0,3); }
    #[test] fn all_missing_is_not_execution_failure() { assert_eq!(finish(&[Observation::Missing;4],0),(4,"NOT_FOUND_OBSERVED")); }
    #[test] fn denied_wins_over_missing() { assert_eq!(finish(&[Observation::Denied,Observation::Missing,Observation::Present,Observation::Present],0).0,5); }
    #[test] fn close_error_invalidates_summary() { assert_eq!(finish(&[Observation::Present;4],5).0,2); }
    #[test] fn all_synthetic_combinations_are_nonzero() {
        let mut bytes=Vec::new(); matrix(&mut bytes).unwrap();
        let text=String::from_utf8(bytes).unwrap(); assert_eq!(text.lines().count(),1250);
        assert!(text.lines().all(|l| !l.ends_with(":0")));
    }
    #[test] fn guid_abi_and_rule_order() {
        assert_eq!(std::mem::size_of::<Guid>(),16); assert_eq!(std::mem::align_of::<Guid>(),4);
        for i in 0..4 { assert_eq!(key(i).d1,0x1649f030+i as u32); }
        assert_eq!(LABELS[0],"auth_connect_v4"); assert_eq!(LABELS[3],"connect_redirect_v6");
    }
    #[test] fn exact_key_strings_match_binary() {
        for i in 0..4 { assert_eq!(format!("{:08x}-25b3-4e01-9ca1-5ca803010019",key(i).d1),KEYS[i]); }
    }
}
