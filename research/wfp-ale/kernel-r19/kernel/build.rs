use std::{env, path::PathBuf};
fn main() {
    assert_eq!(env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("windows"));
    assert_eq!(env::var("CARGO_CFG_TARGET_ARCH").as_deref(), Ok("x86_64"));
    let mut b = bindgen::Builder::default()
        .header("wrapper.h")
        .raw_line("include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/msvc_runtime.rs\"));")
        .clang_args(["-target", "x86_64-pc-windows-msvc", "-fms-extensions", "-fms-compatibility",
            "-D_AMD64_", "-DAMD64", "-D_KERNEL_MODE", "-D_WIN64", "-D_WIN32_WINNT=0x0A00",
            "-DNTDDI_VERSION=0x0A00000C"])
        .use_core().ctypes_prefix("core::ffi").layout_tests(false)
        .derive_debug(false).generate_comments(false).prepend_enum_name(false)
        .allowlist_type("(DRIVER_OBJECT|DEVICE_OBJECT|IRP|UNICODE_STRING|PS_CREATE_NOTIFY_INFO|FWPS_.*|GUID|KSPIN_LOCK|NTSTATUS|BOOLEAN|KIRQL|LARGE_INTEGER|EX_RUNDOWN_REF)")
        .allowlist_function("(IoCreateDevice|WdmlibIoCreateDeviceSecure|IoDeleteDevice|IoCreateSymbolicLink|IoDeleteSymbolicLink|IofCompleteRequest|RtlInitUnicodeString|RtlDowncaseUnicodeString|PsSetCreateProcessNotifyRoutineEx|PsGetProcessId|PsGetProcessCreateTimeQuadPart|PsGetProcessStartKey|ObfReferenceObject|ObfDereferenceObject|KeAcquireSpinLockRaiseToDpc|KeReleaseSpinLock|KeInitializeSpinLock|KeQueryPerformanceCounter|KeBugCheckEx|ExInitializeRundownProtection|ExAcquireRundownProtection|ExReleaseRundownProtection|ExWaitForRundownProtectionRelease|FwpsCalloutRegister1|FwpsCalloutUnregisterById0|FwpsRedirectHandleCreate0|FwpsRedirectHandleDestroy0|FwpsQueryConnectionRedirectState0|FwpsAcquireClassifyHandle0|FwpsReleaseClassifyHandle0|FwpsAcquireWritableLayerDataPointer0|FwpsApplyModifiedLayerData0|ExAllocatePool2|KeQueryInterruptTimePrecise|IoGetRequestorProcess)")
        .allowlist_var("(FB_.*|FWPS_.*|FWP_ACTION_.*|POOL_FLAG_NON_PAGED|FWP_BYTE_BLOB_TYPE|FWP_BYTE_ARRAY16_TYPE|FWP_UINT8|FWP_UINT16|FWP_UINT32|IRP_MJ_.*|DO_DEVICE_INITIALIZING|FILE_DEVICE_UNKNOWN|FILE_DEVICE_SECURE_OPEN)");
    for key in ["FB_WDK_KM", "FB_WDK_CRT", "FB_SDK_SHARED", "FB_SDK_UCRT"] {
        let p = env::var(key).expect(key);
        b = b.clang_arg(format!("-I{p}"));
        println!("cargo:rerun-if-env-changed={key}");
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    b.generate().expect("WDK header binding failed").write_to_file(out.join("wdk.rs")).unwrap();
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=src/msvc_runtime.rs");
    println!("cargo:rustc-link-search=native={}", env::var("FB_WDK_LIB").unwrap());
    // Bind MSVC debug information to the exact archived release image rather
    // than guessing Cargo's linker working directory and name.
    let pdb=env::var("FB_PDB_OUTPUT").expect("Pinned absolute PDB output required");
    assert!(PathBuf::from(&pdb).is_absolute());
    println!("cargo:rerun-if-env-changed=FB_PDB_OUTPUT");
    println!("cargo:rustc-link-arg=/PDB:{pdb}");
    for lib in ["ntoskrnl", "fwpkclnt", "hal", "wdmsec", "BufferOverflowFastFailK", "cng"] { println!("cargo:rustc-link-lib={lib}"); }
    for flag in ["/DEBUG:FULL", "/DRIVER", "/SUBSYSTEM:NATIVE", "/ENTRY:DriverEntry", "/NODEFAULTLIB", "/INTEGRITYCHECK", "/DYNAMICBASE", "/NXCOMPAT", "/OPT:REF,ICF"] {
        println!("cargo:rustc-link-arg={flag}");
    }
}
