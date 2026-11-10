//! R93: read-only, one-shot BFE management inventory of the R19 laboratory policy.
//! This is NOT a packet, origin, CALL_OUT, redirect, enforcement or liveness proof.
//! No filter/callout is installed, mutated, deleted or subscribed to.
//! Windows x86_64 only. No third-party crates, driver, sockets, or service changes.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(windows, target_pointer_width = "64")))]
fn main() {
    eprintln!("R93 requires an already authorized Windows x86_64 user-mode host");
    std::process::exit(2);
}

#[cfg(all(windows, target_pointer_width = "64"))]
mod win {
    use std::ffi::c_void;
    use std::ptr;

    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Guid { data1: u32, data2: u16, data3: u16, data4: [u8; 8] }
    impl Guid {
        const fn from_u128(v: u128) -> Self {
            Self {
                data1: (v >> 96) as u32,
                data2: (v >> 80) as u16,
                data3: (v >> 64) as u16,
                data4: [ (v >> 56) as u8, (v >> 48) as u8,
                         (v >> 40) as u8, (v >> 32) as u8,
                         (v >> 24) as u8, (v >> 16) as u8,
                         (v >> 8) as u8, v as u8 ],
            }
        }
    }
    #[repr(C)]
    struct DisplayData { name: *mut u16, description: *mut u16 }
    #[repr(C)]
    struct ByteBlob { size: u32, data: *mut u8 }
    // Only the stable beginning of FWPM_FILTER0 is read. No union/alignment guess.
    #[repr(C)]
    struct FilterPrefix {
        filter_key: Guid,
        display_data: DisplayData,
        flags: u32,
        provider_key: *mut Guid,
        provider_data: ByteBlob,
        layer_key: Guid,
        sub_layer_key: Guid,
    }
    // Exact FWPM_CALLOUT0 field order, per fwpmtypes.h.
    #[repr(C)]
    struct CalloutView {
        callout_key: Guid,
        display_data: DisplayData,
        flags: u32,
        provider_key: *mut Guid,
        provider_data: ByteBlob,
        applicable_layer: Guid,
        callout_id: u32,
    }
    #[link(name = "fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineOpen0(server: *const u16, authn: u32, identity: *const c_void,
                           session: *const c_void, engine: *mut *mut c_void) -> u32;
        fn FwpmEngineClose0(engine: *mut c_void) -> u32;
        fn FwpmFilterGetByKey0(engine: *mut c_void, key: *const Guid,
                              result: *mut *mut FilterPrefix) -> u32;
        fn FwpmCalloutGetByKey0(engine: *mut c_void, key: *const Guid,
                               result: *mut *mut CalloutView) -> u32;
        fn FwpmFreeMemory0(ptr: *mut *mut c_void);
    }
    const SUB: Guid = Guid::from_u128(0x1649f024_25b3_4e01_9ca1_5ca803010019);
    const FILTER_BASE: u128 = 0x1649f030_25b3_4e01_9ca1_5ca803010019;
    // Matches policy_plan.rs RULES exactly, not the order of kernel callout registration.
    const LABELS: [&str;4] = ["auth_connect_v4", "auth_connect_v6", "connect_redirect_v4", "connect_redirect_v6"];
    const CALLOUTS: [Guid;4] = [
        Guid::from_u128(0x1649f018_25b3_4e01_9ca1_5ca803010019),
        Guid::from_u128(0x1649f019_25b3_4e01_9ca1_5ca803010019),
        Guid::from_u128(0x1649f014_25b3_4e01_9ca1_5ca803010019),
        Guid::from_u128(0x1649f016_25b3_4e01_9ca1_5ca803010019),
    ];
    const RPC_C_AUTHN_WINNT: u32 = 10;
    // fwpmtypes.h: observation-only kernel registration state, not proof of classifyFn.
    const FWPM_CALLOUT_FLAG_REGISTERED: u32 = 0x00040000;

    struct Engine(*mut c_void);
    impl Drop for Engine {
        fn drop(&mut self) { if !self.0.is_null() { unsafe { let _ = FwpmEngineClose0(self.0); } } }
    }
    struct Owned<T>(*mut T);
    impl<T> Drop for Owned<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let mut raw = self.0.cast::<c_void>();
                unsafe { FwpmFreeMemory0(&mut raw); }
            }
        }
    }
    // Only "shape present" or "unavailable". Never a "protected" result.
    pub fn run() -> i32 {
        let mut h: *mut c_void = ptr::null_mut();
        // NULL session and NULL server: local read-only management query.
        let open = unsafe { FwpmEngineOpen0(ptr::null(), RPC_C_AUTHN_WINNT,
                                            ptr::null(), ptr::null(), &mut h) };
        if open != 0 || h.is_null() {
            println!("{{\"status\":\"unavailable\",\"stage\":\"open\",\"code\":{open}}}");
            return 2;
        }
        let engine = Engine(h);
        let mut shape_complete = true;
        let mut registered_snapshot_complete = true;
        for i in 0..4usize {
            let key = Guid::from_u128(FILTER_BASE + ((i as u128) << 96));
            let mut f: *mut FilterPrefix = ptr::null_mut();
            let fs = unsafe { FwpmFilterGetByKey0(engine.0, &key, &mut f) };
            let filter = Owned(f);
            let mut c: *mut CalloutView = ptr::null_mut();
            let cs = unsafe { FwpmCalloutGetByKey0(engine.0, &CALLOUTS[i], &mut c) };
            let callout = Owned(c);
            let shape = if fs == 0 && cs == 0 && !filter.0.is_null() && !callout.0.is_null() {
                let fv = unsafe { &*filter.0 };
                let cv = unsafe { &*callout.0 };
                fv.filter_key == key && fv.sub_layer_key == SUB && fv.flags == 0 &&
                cv.callout_key == CALLOUTS[i] && fv.layer_key == cv.applicable_layer
            } else { false };
            shape_complete &= shape;
            let flags = if callout.0.is_null() { 0 } else { unsafe { (*callout.0).flags } };
            // Missing or unregistered runtime callout must not pass this snapshot gate.
            let kernel_registered = cs == 0 && !callout.0.is_null() &&
                (flags & FWPM_CALLOUT_FLAG_REGISTERED) != 0;
            registered_snapshot_complete &= kernel_registered;
            println!("{{\"rule\":\"{}\",\"filter_status\":{},\"callout_status\":{},\"callout_flags\":{},\"kernel_registered\":{kernel_registered},\"shape_present\":{shape}}}",
                     LABELS[i], fs, cs, flags);
        }
        // A complete snapshot does not certify a live classifyFn, conditions,
        // current AppId, flow origin, filter enforcement, or future presence.
        let snapshot_gate_complete = shape_complete && registered_snapshot_complete;
        println!("{{\"inventory_shape_complete\":{shape_complete},\"registered_snapshot_complete\":{registered_snapshot_complete},\"snapshot_gate_complete\":{snapshot_gate_complete},\"kernel_origin_proof\":false,\"continuous_enforcement_proof\":false}}");
        if snapshot_gate_complete { 0 } else { 3 }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test] fn keys_match_source_order() {
            for i in 0..4u128 {
                assert_eq!(Guid::from_u128(FILTER_BASE + (i << 96)).data1,
                           0x1649f030 + i as u32);
            }
            assert_eq!(CALLOUTS.map(|x| x.data1), [0x1649f018,0x1649f019,0x1649f014,0x1649f016]);
        }
        #[test] fn registered_flag_is_not_merely_callout_presence() {
            assert_eq!(FWPM_CALLOUT_FLAG_REGISTERED, 0x00040000);
            assert_eq!(0x00010000 & FWPM_CALLOUT_FLAG_REGISTERED, 0);
            assert_ne!((0x00010000 | FWPM_CALLOUT_FLAG_REGISTERED) & FWPM_CALLOUT_FLAG_REGISTERED, 0);
        }
        #[test] fn ffi_prefix_alignment_x64() {
            assert_eq!(std::mem::size_of::<Guid>(),16);
            assert_eq!(std::mem::size_of::<ByteBlob>(),16);
            assert_eq!(std::mem::offset_of!(FilterPrefix, layer_key),64);
            assert_eq!(std::mem::offset_of!(FilterPrefix, sub_layer_key),80);
            assert_eq!(std::mem::offset_of!(CalloutView, applicable_layer),64);
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn main() { std::process::exit(win::run()); }
