// Original minimal MSVC ABI support for a panic=abort no_std kernel image.
// Microsoft windows-drivers-rs documents these compiler-emitted symbols in
// crates/wdk-sys/src/lib.rs. No C/C++ runtime or exception unwinder is linked.
// _fltused is a linker marker, not floating-point-state initialization.
#[no_mangle]
pub static _fltused: i32 = 0;

// A prebuilt core object can retain an MSVC C++ personality reference even
// with panic=abort. Do NOT return a fake success disposition: an unexpected
// unwind is fatal. All four ABI parameters are ignored and never dereferenced.
#[cfg(panic = "abort")]
#[no_mangle]
pub unsafe extern "C" fn __CxxFrameHandler3(
    _exception: *mut core::ffi::c_void,
    _frame: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
    _dispatcher: *mut core::ffi::c_void,
) -> ! {
    KeBugCheckEx(0xE2, 0x47323139, 0, 4, 0)
}
