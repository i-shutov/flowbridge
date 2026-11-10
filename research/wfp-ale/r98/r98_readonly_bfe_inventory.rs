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
    use std::{ffi::{c_void,OsStr},os::windows::ffi::OsStrExt,ptr,slice};

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
    #[repr(C)]
    struct FilterCondition { field_key: Guid, match_type: u32, value: FwpValueOpaque }
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
        filter_conditions: *mut FilterCondition,
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
        fn FwpmGetAppIdFromFileName0(file_name: *const u16, app_id: *mut *mut ByteBlob) -> u32;
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

    // Expected exact ALE layer and filtering-condition identities per Windows SDK.
    const LAYERS: [Guid;4] = [
        Guid::from_u128(0xc38d57d1_05a7_4c33_904f_7fbceee60e82),
        Guid::from_u128(0x4a72393b_319f_44bc_84c3_ba54dcb3b6b4),
        Guid::from_u128(0xc6e63c8c_b784_4562_aa7d_0a67cfcaf9a3),
        Guid::from_u128(0x587e54a7_8046_42ba_a0aa_b716250fc7fd),
    ];
    const IP_PROTOCOL: Guid=Guid::from_u128(0x3971ef2b_623e_4f9a_8cb1_6e79b806b9a7);
    const APP_ID: Guid=Guid::from_u128(0xd78e1e87_8644_4ea5_9437_d809ecefc971);
    const ORIGINAL_APP_ID: Guid=Guid::from_u128(0x0e6cd086_e1fb_4212_842f_8a9f993fb3f6);
    // Only these two conditions are accepted, in either order, without extras.
    fn strict_conditions(ptr: *mut FilterCondition, count: u32, auth: bool, appid: &[u8]) -> bool {
        if count != 2 || ptr.is_null() || appid.len() < 4 || appid.len() > 514 ||
            appid.len() % 2 != 0 { return false; }
        // Entire filter allocation stays owned until check returns.
        let values = unsafe { slice::from_raw_parts(ptr, 2) };
        let want = if auth { ORIGINAL_APP_ID } else { APP_ID };
        let (mut app, mut tcp) = (false, false);
        for c in values {
            if c.field_key == want && c.match_type == 0 && c.value.data_type == 12 {
                if app { return false; }
                let p = c.value._value_bits as usize as *const ByteBlob;
                if p.is_null() { return false; }
                let b = unsafe { &*p };
                if b.size as usize != appid.len() || b.data.is_null() { return false; }
                if unsafe { slice::from_raw_parts(b.data, appid.len()) } != appid { return false; }
                app = true;
            } else if c.field_key == IP_PROTOCOL && c.match_type == 0 && c.value.data_type == 1 {
                if tcp || (c.value._value_bits as u8) != 6 { return false; }
                tcp = true;
            } else { return false; }
        }
        app && tcp
    }
    fn selected_appid(file: &OsStr) -> Result<Vec<u8>,u32> {
        let path:Vec<u16> = file.encode_wide().chain(std::iter::once(0)).collect();
        let mut p:*mut ByteBlob=ptr::null_mut();
        let status=unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(),&mut p) };
        let owner=Owned(p);
        if status != 0 || owner.0.is_null() { return Err(if status==0 { 1 } else { status }); }
        let b=unsafe { &*owner.0 };
        if b.size < 4 || b.size > 514 || b.size % 2 != 0 || b.data.is_null() {
            return Err(1);
        }
        Ok(unsafe { slice::from_raw_parts(b.data,b.size as usize) }.to_vec())
    }
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
    pub fn run(file: &OsStr) -> i32 {
        let appid=match selected_appid(file) {
            Ok(v)=>v,
            Err(code)=>{
                println!("{{\"status\":\"unavailable\",\"stage\":\"appid\",\"code\":{code}}}");
                return 2;
            }
        };
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
        let mut layer_complete = true;
        let mut conditions_complete = true;
        for i in 0..4usize {
            let key = Guid::from_u128(FILTER_BASE + ((i as u128) << 96));
            let mut f: *mut FilterView = ptr::null_mut();
            let fs = unsafe { FwpmFilterGetByKey0(engine.0, &key, &mut f) };
            let filter = Owned(f);
            let mut c: *mut CalloutView = ptr::null_mut();
            let cs = unsafe { FwpmCalloutGetByKey0(engine.0, &CALLOUTS[i], &mut c) };
            let callout = Owned(c);
            let (shape, action_and_count, exact_layer, exact_conditions) =
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
                    let exact_layer = fv.layer_key == LAYERS[i] &&
                        cv.applicable_layer == LAYERS[i];
                    let exact_conditions = strict_conditions(
                        fv.filter_conditions, fv.num_filter_conditions, i < 2, &appid
                    );
                    (shape, action_and_count, exact_layer, exact_conditions)
                } else { (false, false, false, false) };
            shape_complete &= shape;
            action_and_count_complete &= action_and_count;
            layer_complete &= exact_layer;
            conditions_complete &= exact_conditions;
            let flags = if callout.0.is_null() { 0 } else { unsafe { (*callout.0).flags } };
            // Missing or unregistered runtime callout must not pass this snapshot gate.
            let kernel_registered = cs == 0 && !callout.0.is_null() &&
                (flags & FWPM_CALLOUT_FLAG_REGISTERED) != 0;
            registered_snapshot_complete &= kernel_registered;
            println!("{{\"rule\":\"{}\",\"filter_status\":{},\"callout_status\":{},\"callout_flags\":{},\"kernel_registered\":{kernel_registered},\"shape_present\":{shape},\"action_and_count_matches\":{action_and_count},\"exact_layer\":{exact_layer},\"exact_conditions\":{exact_conditions}}}",
                     LABELS[i], fs, cs, flags);
        }
        // A complete snapshot does not certify a live classifyFn, conditions,
        // current AppId, flow origin, filter enforcement, or future presence.
        let snapshot_gate_complete = shape_complete && registered_snapshot_complete &&
            action_and_count_complete && layer_complete && conditions_complete;
        println!("{{\"inventory_shape_complete\":{shape_complete},\"registered_snapshot_complete\":{registered_snapshot_complete},\"action_and_count_complete\":{action_and_count_complete},\"exact_layer_complete\":{layer_complete},\"exact_conditions_complete\":{conditions_complete},\"snapshot_gate_complete\":{snapshot_gate_complete},\"kernel_origin_proof\":false,\"continuous_enforcement_proof\":false}}");
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
            assert_eq!(std::mem::size_of::<FilterCondition>(),40);
            assert_eq!(std::mem::offset_of!(FilterCondition, value),24);
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn main() {
    use std::{env,process};
    let mut args=env::args_os(); let _bin=args.next();
    let file=match (args.next(),args.next()){
        (Some(path),None)=>path,
        _=>{eprintln!("usage: r98_inventory.exe <local-selected-exe-path>");process::exit(2)}
    };
    let path=file.to_string_lossy();
    let b=path.as_bytes();
    if b.len()<4 || !b[0].is_ascii_alphabetic() || b[1]!=b':' || b[2]!=b'\\' {
        eprintln!("requires a local drive-rooted executable path, no UNC/network");
        process::exit(2);
    }
    process::exit(win::run(file.as_os_str()));
}
