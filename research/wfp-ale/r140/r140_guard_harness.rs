//! R140: import the exact shared kernel action-rights module by path.
//! Synthetic test-only executable; no driver, socket, FFI, BFE or policy mutation.
#![forbid(unsafe_code)]
#[path="../kernel-r19/kernel/src/action_rights.rs"]
mod action_rights;
use std::io::{self,Write};
use action_rights::{Snapshot,try_block};
fn matrix(mut out:impl Write)->io::Result<()> {
    let rights=[0u32,1,2,3,0x100,0x101,u32::MAX];
    let actions=[0u32,0x11,0x12,0x26,7,0x1234];
    for r in rights {for a in actions {
        let mut sample=Snapshot{rights:r,action:a};
        let changed=try_block(&mut sample,1,0x12,0x11);
        writeln!(out,"{r}:{a}:{}:{}:{}",u8::from(changed),sample.rights,sample.action)?;
    }}Ok(())
}
fn main(){
    if std::env::args().skip(1).collect::<Vec<_>>()!=["--matrix"] {
        eprintln!("usage: r140_guard_harness --matrix");std::process::exit(2);
    }
    if matrix(io::stdout().lock()).is_err(){std::process::exit(2);}
}
#[cfg(test)]mod harness_tests{
    use super::*;
    #[test]fn matrix_count(){let mut b=Vec::new();matrix(&mut b).unwrap();assert_eq!(String::from_utf8(b).unwrap().lines().count(),42);}
    #[test]fn no_out_of_rights_action_write(){
        for a in [0,0x11,0x26,7]{let mut s=Snapshot{rights:0,action:a};let v=s;
            assert!(!try_block(&mut s,1,0x12,0x11));assert_eq!(s,v);}
    }
    #[test]fn return_is_not_system_wfp_proof(){assert!(include_str!("../kernel-r19/kernel/src/action_rights.rs").contains("persistent OS kill switch"));}
}
