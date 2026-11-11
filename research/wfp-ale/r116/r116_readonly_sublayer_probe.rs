//! R116 independent read-only BFE sublayer descriptor probe.
//! NEVER confers kernel callback, packet provenance or no-DIRECT evidence.
//! No filter creation, no driver, no socket, no services or system changes.
#![deny(unsafe_op_in_unsafe_fn)]

const EXPECTED_WEIGHT: u16 = 0x7000;
const EXPECTED_KEY: u128 = 0x1649f024_25b3_4e01_9ca1_5ca803010019;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    key: u128,
    flags: u32,
    has_provider: bool,
    weight: u16,
}

// A descriptor check is a necessary structural observation, not a live
// filter/flow verdict. It is intentionally unable to return GO/PASS.
fn matches_r19_descriptor(s: Snapshot) -> bool {
    s.key == EXPECTED_KEY
        && s.flags == 0
        && !s.has_provider
        && s.weight == EXPECTED_WEIGHT
}

#[cfg(not(all(windows, target_pointer_width = "64")))]
fn main() {
    eprintln!("UNAVAILABLE: R116 requires authorized Windows x64 user-mode");
    std::process::exit(2);
}

#[cfg(all(windows, target_pointer_width = "64"))]
mod windows_readonly {
    use super::{matches_r19_descriptor, Snapshot, EXPECTED_KEY};
    use std::{ffi::c_void, ptr};

    // Exact x64 C layouts from official fwpmtypes.h / fwptypes.h.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Guid { d1: u32, d2: u16, d3: u16, d4: [u8; 8] }
    impl Guid {
        const fn from_u128(n: u128) -> Self {
            Self {
                d1: (n >> 96) as u32, d2: (n >> 80) as u16, d3: (n >> 64) as u16,
                d4: [(n >> 56) as u8, (n >> 48) as u8, (n >> 40) as u8, (n >> 32) as u8,
                     (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
            }
        }
        fn as_u128(self) -> u128 {
            ((self.d1 as u128) << 96) | ((self.d2 as u128) << 80)
                | ((self.d3 as u128) << 64)
                | self.d4.iter().fold(0u128, |v, b| (v << 8) | (*b as u128))
        }
    }
    #[repr(C)] struct DisplayData { name: *mut u16, description: *mut u16 }
    #[repr(C)] struct Blob { size: u32, data: *mut u8 }
    #[repr(C)] struct SubLayer {
        key: Guid,
        display: DisplayData,
        flags: u32,
        provider: *mut Guid,
        provider_data: Blob,
        weight: u16,
    }
    const RPC_C_AUTHN_WINNT: u32 = 10;

    #[link(name = "fwpuclnt")]
    unsafe extern "system" {
        fn FwpmEngineOpen0(server: *const u16, authn: u32, id: *const c_void,
            session: *const c_void, engine: *mut *mut c_void) -> u32;
        fn FwpmEngineClose0(engine: *mut c_void) -> u32;
        fn FwpmSubLayerGetByKey0(engine: *mut c_void, key: *const Guid,
            found: *mut *mut SubLayer) -> u32;
        fn FwpmFreeMemory0(p: *mut *mut c_void);
    }
    struct Engine(*mut c_void);
    impl Drop for Engine {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { let _ = FwpmEngineClose0(self.0); } }
        }
    }
    struct OwnedSubLayer(*mut SubLayer);
    impl Drop for OwnedSubLayer {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let mut raw = self.0.cast::<c_void>();
                unsafe { FwpmFreeMemory0(&mut raw); }
            }
        }
    }
    fn read() -> Result<Snapshot, (&'static str, u32)> {
        // FwpmSubLayerGetByKey0 is management-plane only; it is NOT part of
        // the R103 enumerator snapshot and can race concurrent BFE mutations.
        let mut ptr_engine = ptr::null_mut();
        let code = unsafe { FwpmEngineOpen0(ptr::null(), RPC_C_AUTHN_WINNT,
            ptr::null(), ptr::null(), &mut ptr_engine) };
        if code != 0 || ptr_engine.is_null() { return Err(("open", if code == 0 { 1 } else { code })); }
        let engine = Engine(ptr_engine);
        let key = Guid::from_u128(EXPECTED_KEY);
        let mut raw_sub = ptr::null_mut();
        let code = unsafe { FwpmSubLayerGetByKey0(engine.0, &key, &mut raw_sub) };
        let owned = OwnedSubLayer(raw_sub);
        if code != 0 || owned.0.is_null() {
            return Err(("get_sublayer", if code == 0 { 1 } else { code }));
        }
        let sub = unsafe { &*owned.0 };
        Ok(Snapshot {
            key: sub.key.as_u128(),
            flags: sub.flags,
            has_provider: !sub.provider.is_null(),
            weight: sub.weight,
        })
    }
    pub fn run() -> i32 {
        match read() {
            Err((stage, code)) => {
                println!("{{\"status\":\"UNKNOWN\",\"stage\":\"{}\",\"code\":{},\"kernel_proof\":false,\"no_direct_proof\":false}}", stage, code);
                2
            }
            Ok(desc) if matches_r19_descriptor(desc) => {
                println!("{{\"status\":\"SUBLAYER_DESCRIPTOR_MATCH_ONLY\",\"weight\":{},\"flags\":0,\"provider_null\":true,\"temporal_join_unverified\":true,\"acl_hidden_filters_possible\":true,\"kernel_proof\":false,\"no_direct_proof\":false}}", desc.weight);
                4 // Still UNKNOWN, never PASS
            }
            Ok(desc) => {
                println!("{{\"status\":\"UNKNOWN_SUBLAYER_DESCRIPTOR_CHANGED\",\"weight\":{},\"flags\":{},\"provider_null\":{},\"temporal_join_unverified\":true,\"kernel_proof\":false,\"no_direct_proof\":false}}",
                         desc.weight, desc.flags, !desc.has_provider);
                2
            }
        }
    }

    #[cfg(test)]
    mod abi_tests {
        use super::*;
        #[test]
        fn x64_layout() {
            assert_eq!(std::mem::size_of::<Guid>(), 16);
            assert_eq!(std::mem::size_of::<Blob>(), 16);
            assert_eq!(std::mem::offset_of!(SubLayer, flags), 32);
            assert_eq!(std::mem::offset_of!(SubLayer, provider), 40);
            assert_eq!(std::mem::offset_of!(SubLayer, provider_data), 48);
            assert_eq!(std::mem::offset_of!(SubLayer, weight), 64);
            assert_eq!(std::mem::size_of::<SubLayer>(), 72);
        }
        #[test]
        fn round_trip_guid() {
            assert_eq!(Guid::from_u128(EXPECTED_KEY).as_u128(), EXPECTED_KEY);
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn main() { std::process::exit(windows_readonly::run()); }

#[cfg(test)]
mod model_tests {
    use super::*;
    fn sample() -> Snapshot { Snapshot {key: EXPECTED_KEY, flags: 0, has_provider: false, weight: EXPECTED_WEIGHT} }
    #[test] fn exact_match_is_not_a_proof() { assert!(matches_r19_descriptor(sample())); }
    #[test] fn sublayer_priority_drift_is_detected() {
        for weight in [0, 1, 0x6fff, 0x7001, u16::MAX] {
            assert!(!matches_r19_descriptor(Snapshot {weight, ..sample()}));
        }
    }
    #[test] fn spoofed_shape_is_detected() {
        assert!(!matches_r19_descriptor(Snapshot {key: EXPECTED_KEY ^ 1, ..sample()}));
        assert!(!matches_r19_descriptor(Snapshot {flags: 1, ..sample()}));
        assert!(!matches_r19_descriptor(Snapshot {has_provider: true, ..sample()}));
    }
}
