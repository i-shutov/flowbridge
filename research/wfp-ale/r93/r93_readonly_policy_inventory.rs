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
    // x64 FWP_VALUE0: 32-bit type, padding and opaque eight-byte union.
    // Union bytes are never read/dereferenced.
    #[repr(C)]
    struct FwpValueOpaque { data_type: u32, _pad: u32, _value_bits: u64 }
    // FWPM_ACTION0: 32-bit action type and GUID calloutKey/filterType union.
    #[repr(C)]
    struct FilterAction { action_type: u32, callout_key: Guid }
    #[repr(C)]
    struct FilterView {
        filter_key: Guid,
        display_data: DisplayData,
        flags: u32,
        provider_key: *mut Guid,
        provider_data: ByteBlob,
        layer_key: Guid,
        sub_layer_key: Guid,
        weight: FwpValueOpaque,
        num_filter_conditions: u32,
        filter_conditions: *mut c_void,
        action: FilterAction,
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
                              result: *mut *mut FilterView) -> u32;
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
    const ACTION_TYPES: [u32;4] = [
        0x00005003, 0x00005003, // AUTH: CALLOUT_TERMINATING
        0x00004005, 0x00004005, // REDIRECT: CALLOUT_UNKNOWN
    ];

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
        let mut action_and_count_complete = true;
        for i in 0..4usize {
            let key = Guid::from_u128(FILTER_BASE + ((i as u128) << 96));
            let mut f: *mut FilterView = ptr::null_mut();
            let fs = unsafe { FwpmFilterGetByKey0(engine.0, &key, &mut f) };
            let filter = Owned(f);
            let mut c: *mut CalloutView = ptr::null_mut();
            let cs = unsafe { FwpmCalloutGetByKey0(engine.0, &CALLOUTS[i], &mut c) };
            let callout = Owned(c);
            let (shape, action_and_count) =
                if fs == 0 && cs == 0 && !filter.0.is_null() && !callout.0.is_null() {
                    let fv = unsafe { &*filter.0 };
                    let cv = unsafe { &*callout.0 };
                    let shape = fv.filter_key == key && fv.sub_layer_key == SUB &&
                        fv.flags == 0 && cv.callout_key == CALLOUTS[i] &&
                        fv.layer_key == cv.applicable_layer;
                    // R19 installs two scoped conditions. This checks count and
                    // pointer presence, NOT condition contents or AppId.
                    let action_and_count = fv.num_filter_conditions == 2 &&
                        !fv.filter_conditions.is_null() &&
                        fv.action.action_type == ACTION_TYPES[i] &&
                        fv.action.callout_key == CALLOUTS[i];
                    (shape, action_and_count)
                } else { (false, false) };
            shape_complete &= shape;
            action_and_count_complete &= action_and_count;
            let flags = if callout.0.is_null() { 0 } else { unsafe { (*callout.0).flags } };
            // Missing or unregistered runtime callout must not pass this snapshot gate.
            let kernel_registered = cs == 0 && !callout.0.is_null() &&
                (flags & FWPM_CALLOUT_FLAG_REGISTERED) != 0;
            registered_snapshot_complete &= kernel_registered;
            println!("{{\"rule\":\"{}\",\"filter_status\":{},\"callout_status\":{},\"callout_flags\":{},\"kernel_registered\":{kernel_registered},\"shape_present\":{shape},\"action_and_count_matches\":{action_and_count}}}",
                     LABELS[i], fs, cs, flags);
        }
        // A complete snapshot does not certify a live classifyFn, conditions,
        // current AppId, flow origin, filter enforcement, or future presence.
        let snapshot_gate_complete = shape_complete && registered_snapshot_complete &&
            action_and_count_complete;
        println!("{{\"inventory_shape_complete\":{shape_complete},\"registered_snapshot_complete\":{registered_snapshot_complete},\"action_and_count_complete\":{action_and_count_complete},\"snapshot_gate_complete\":{snapshot_gate_complete},\"kernel_origin_proof\":false,\"continuous_enforcement_proof\":false}}");
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
        #[test] fn action_types_are_not_permit_or_inspection() {
            assert_eq!(ACTION_TYPES, [0x5003,0x5003,0x4005,0x4005]);
            for action in ACTION_TYPES { assert_ne!(action,0x1002); assert_ne!(action,0x6004); }
        }
        #[test] fn ffi_prefix_alignment_x64() {
            assert_eq!(std::mem::size_of::<Guid>(),16);
            assert_eq!(std::mem::size_of::<ByteBlob>(),16);
            assert_eq!(std::mem::offset_of!(FilterView, layer_key),64);
            assert_eq!(std::mem::offset_of!(FilterView, sub_layer_key),80);
            assert_eq!(std::mem::offset_of!(CalloutView, applicable_layer),64);
            assert_eq!(std::mem::size_of::<FwpValueOpaque>(),16);
            assert_eq!(std::mem::align_of::<FwpValueOpaque>(),8);
            assert_eq!(std::mem::size_of::<FilterAction>(),20);
            assert_eq!(std::mem::offset_of!(FilterView, weight),96);
            assert_eq!(std::mem::offset_of!(FilterView, num_filter_conditions),112);
            assert_eq!(std::mem::offset_of!(FilterView, filter_conditions),120);
            assert_eq!(std::mem::offset_of!(FilterView, action),128);
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn main() { std::process::exit(win::run()); }
