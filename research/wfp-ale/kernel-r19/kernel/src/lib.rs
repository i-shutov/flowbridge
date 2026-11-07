//! Original Rust WDM redirect backend. BUILD-ONLY / NOT NATIVE-ACCEPTED.
//! Registers kernel callbacks; redirect remains unarmed until broker configuration. No filter installer.
//! An approved external lab policy is necessary to invoke the ALE callouts.
//! Process/EXE refs originate at process creation, not a late numeric-PID lookup.
#![no_std]
#![allow(non_snake_case)]
use core::{cell::UnsafeCell, ffi::c_void, mem, ptr, slice, sync::atomic::{AtomicBool,Ordering}};
#[allow(dead_code,non_snake_case,non_camel_case_types,non_upper_case_globals,improper_ctypes,unused_imports)]
mod k { include!(concat!(env!("OUT_DIR"), "/wdk.rs")); }
mod ledger;
mod handoff;
mod redirect;
use ledger::{Ledger,Owner,Witness,MAX_NAME};

struct Cell<T>(UnsafeCell<T>); unsafe impl<T> Sync for Cell<T> {}
static STATE: Cell<Ledger> = Cell(UnsafeCell::new(Ledger::new()));
static STOP: AtomicBool = AtomicBool::new(false);
static mut LOCK: k::KSPIN_LOCK = 0;
static mut RUNDOWN: k::EX_RUNDOWN_REF = unsafe { mem::zeroed() };
static mut DEVICE: *mut k::DEVICE_OBJECT = ptr::null_mut();
static mut IDS: [u32;4] = [0;4];
static mut PROCESS_NOTIFY: bool = false;
static mut LINK_CREATED: bool = false;
const SUCCESS:i32=0;
const INVALID:i32=0xC000000Du32 as i32;
const DENIED:i32=0xC0000022u32 as i32;
const NOT_READY:i32=0xC00000A3u32 as i32;
const BUFFER_SMALL:i32=0xC0000023u32 as i32;
const EMPTY:i32=0x8000001Au32 as i32;
const GUARD_GUID:k::GUID=k::GUID{Data1:0x1649f013,Data2:0x25b3,Data3:0x4e01,Data4:[0x9c,0xa1,0x5c,0xa8,0x03,0x01,0x00,0x19]};
const V4_GUID:k::GUID=k::GUID{Data1:0x1649f014,Data2:0x25b3,Data3:0x4e01,Data4:[0x9c,0xa1,0x5c,0xa8,0x03,0x01,0x00,0x19]};
const V6_GUID:k::GUID=k::GUID{Data1:0x1649f016,Data2:0x25b3,Data3:0x4e01,Data4:[0x9c,0xa1,0x5c,0xa8,0x03,0x01,0x00,0x19]};
const AUTH_V4_GUID:k::GUID=k::GUID{Data1:0x1649f018,Data2:0x25b3,Data3:0x4e01,Data4:[0x9c,0xa1,0x5c,0xa8,0x03,0x01,0x00,0x19]};
const AUTH_V6_GUID:k::GUID=k::GUID{Data1:0x1649f019,Data2:0x25b3,Data3:0x4e01,Data4:[0x9c,0xa1,0x5c,0xa8,0x03,0x01,0x00,0x19]};
const fn wide<const N:usize>(s:&[u8])->[u16;N]{let mut v=[0;N];let mut i=0;while i<s.len(){v[i]=s[i] as u16;i+=1;}v}
const DEV:[u16;31]=wide(b"\\Device\\FlowBridgeG2WitnessR19");
const LINK:[u16;35]=wide(b"\\DosDevices\\FlowBridgeG2WitnessR19");
const SDDL:[u16;35]=wide(b"D:P(A;;GRGW;;;SY)(A;;GRGW;;;BA)");

unsafe fn unicode(s:*const u16)->k::UNICODE_STRING {let mut u=mem::zeroed();k::RtlInitUnicodeString(&mut u,s);u}
struct Guard(u8);
impl Guard {unsafe fn take()->Self{Self(k::KeAcquireSpinLockRaiseToDpc(ptr::addr_of_mut!(LOCK)))}}
impl Drop for Guard {fn drop(&mut self){unsafe{k::KeReleaseSpinLock(ptr::addr_of_mut!(LOCK),self.0)}}}
struct Active;
impl Active {unsafe fn enter()->Option<Self>{if k::ExAcquireRundownProtection(ptr::addr_of_mut!(RUNDOWN))!=0{Some(Self)}else{None}}}
impl Drop for Active {fn drop(&mut self){unsafe{k::ExReleaseRundownProtection(ptr::addr_of_mut!(RUNDOWN));}}}
// Only compile-time nonnegative offsets generated from WDK offsetof are accepted here.
unsafe fn read_at<T:Copy>(base:*const c_void,offset:i32)->T{ptr::read_unaligned(base.cast::<u8>().add(offset as usize).cast())}
unsafe fn write_at<T>(base:*mut c_void,offset:i32,v:T){ptr::write_unaligned(base.cast::<u8>().add(offset as usize).cast(),v);}

unsafe extern "C" fn process_event(process:k::PEPROCESS,pid:k::HANDLE,info:*mut k::PS_CREATE_NOTIFY_INFO) {
    let Some(_active)=Active::enter() else{return};
    if STOP.load(Ordering::Acquire) || process.is_null(){return;}
    let id=pid as usize as u64;
    if info.is_null(){let _lock=Guard::take();(*STATE.0.get()).died(id,process as usize);redirect::process_exit(id);return;}
    let c=&*info;
    if c.Size < mem::size_of::<k::PS_CREATE_NOTIFY_INFO>() as k::SIZE_T || c.CreationStatus<0
        || c.FileObject.is_null() || c.ImageFileName.is_null(){return;}
    // WDK MSVC x64 layout: first bit of the ULONG immediately after Size is
    // FileOpenNameAvailable. The wrapper derives the offset from SIZE_T.
    let flags:u32=read_at(info.cast(),k::FB_CREATE_FLAGS);
    if flags&1==0 || flags&2!=0{return;}
    let name=&*c.ImageFileName;
    if name.Buffer.is_null() || name.Length==0 || name.Length as usize>MAX_NAME || name.Length%2!=0{return;}
    let mut lowered=[0u16;MAX_NAME/2];
    let mut dst=k::UNICODE_STRING{Length:0,MaximumLength:MAX_NAME as u16,Buffer:lowered.as_mut_ptr()};
    // Process-create callback runs at PASSIVE_LEVEL; no pageable name operation in classify.
    if k::RtlDowncaseUnicodeString(&mut dst,c.ImageFileName,0)<0{return;}
    let epoch=k::PsGetProcessCreateTimeQuadPart(process) as u64;
    let start=k::PsGetProcessStartKey(process);
    if k::PsGetProcessId(process)!=pid || epoch==0 || start==0{return;}
    let mut owner=Owner::EMPTY;
    owner.pid=id;owner.process=process as usize;owner.file=c.FileObject as usize;
    owner.epoch=epoch;owner.start_key=start;owner.live=true;owner.name_len=dst.Length as usize;
    owner.name[..owner.name_len].copy_from_slice(slice::from_raw_parts(lowered.as_ptr().cast(),owner.name_len));
    k::ObfReferenceObject(process.cast());k::ObfReferenceObject(c.FileObject.cast());
    let accepted={let _lock=Guard::take();(*STATE.0.get()).born(owner).is_ok()};
    if !accepted{k::ObfDereferenceObject(c.FileObject.cast());k::ObfDereferenceObject(process.cast());}
}

unsafe extern "C" fn classify(values:*const k::FWPS_INCOMING_VALUES0,meta:*const k::FWPS_INCOMING_METADATA_VALUES0,
    _layer:*mut c_void,_context:*const c_void,_filter:*const k::FWPS_FILTER1,_flow:u64,out:*mut k::FWPS_CLASSIFY_OUT0) {
    // Unarmed callbacks continue; selected armed traffic is decided by redirect.rs.
    if !out.is_null() && (*out).rights & k::FWPS_RIGHT_ACTION_WRITE!=0{(*out).actionType=k::FWP_ACTION_CONTINUE;}
    let Some(_active)=Active::enter() else{if !out.is_null(){(*out).actionType=k::FWP_ACTION_BLOCK;(*out).rights&=!k::FWPS_RIGHT_ACTION_WRITE;}return};
    if STOP.load(Ordering::Acquire){if !out.is_null(){(*out).actionType=k::FWP_ACTION_BLOCK;(*out).rights&=!k::FWPS_RIGHT_ACTION_WRITE;}return;}
    redirect::classify(values,meta,_context,_filter,out);
}
unsafe extern "C" fn auth_callback(values:*const k::FWPS_INCOMING_VALUES0,meta:*const k::FWPS_INCOMING_METADATA_VALUES0,
    _layer:*mut c_void,_context:*const c_void,_filter:*const k::FWPS_FILTER1,_flow:u64,out:*mut k::FWPS_CLASSIFY_OUT0) {
    let Some(_active)=Active::enter() else {
        if !out.is_null(){(*out).actionType=k::FWP_ACTION_BLOCK;(*out).rights&=!k::FWPS_RIGHT_ACTION_WRITE;}
        return;
    };
    if STOP.load(Ordering::Acquire){
        if !out.is_null(){(*out).actionType=k::FWP_ACTION_BLOCK;(*out).rights&=!k::FWPS_RIGHT_ACTION_WRITE;}
        return;
    }
    redirect::auth_classify(values,meta,out);
}
unsafe extern "C" fn notify(_ty:k::FWPS_CALLOUT_NOTIFY_TYPE,_key:*const k::GUID,_filter:*mut k::FWPS_FILTER1)->i32{SUCCESS}

unsafe fn complete(irp:*mut k::IRP,status:i32,bytes:usize)->i32 {
    write_at(irp.cast(),k::FB_IRP_STATUS,status);write_at(irp.cast(),k::FB_IRP_INFORMATION,bytes);
    k::IofCompleteRequest(irp,0);status
}
unsafe extern "C" fn dispatch(_dev:*mut k::DEVICE_OBJECT,irp:*mut k::IRP)->i32 {
    if irp.is_null(){return INVALID;}
    let Some(_active)=Active::enter() else{return complete(irp,NOT_READY,0)};
    if STOP.load(Ordering::Acquire){return complete(irp,NOT_READY,0);}
    let stack:*const c_void=read_at(irp.cast(),k::FB_IRP_STACK);
    if stack.is_null(){return complete(irp,INVALID,0);}
    let major:u8=read_at(stack,k::FB_STACK_MAJOR);
    if major==k::IRP_MJ_CREATE as u8||major==k::IRP_MJ_CLOSE as u8{return complete(irp,SUCCESS,0);}
    if major!=k::IRP_MJ_DEVICE_CONTROL as u8{return complete(irp,DENIED,0);}
    let code=read_at::<u32>(stack,k::FB_STACK_CODE);
    if matches!(code,handoff::ARM|handoff::CLAIM|handoff::PING|handoff::STOP){
        let length=read_at::<u32>(stack,k::FB_STACK_INPUT) as usize;
        let buffer:*const u8=read_at(irp.cast(),k::FB_IRP_BUFFER);
        if length>handoff::ARM_LEN || (length>0 && buffer.is_null()){return complete(irp,INVALID,0);}
        let input=if length==0{&[]}else{slice::from_raw_parts(buffer,length)};
        let status=redirect::ioctl(code,input,k::IoGetRequestorProcess(irp));
        return complete(irp,status,0);
    }
    if code!=k::FB_WITNESS_IOCTL as u32{return complete(irp,DENIED,0);}
    let length:u32=read_at(stack,k::FB_STACK_OUTPUT);
    let buffer:*mut c_void=read_at(irp.cast(),k::FB_IRP_BUFFER);
    if buffer.is_null() || (length as usize)<mem::size_of::<Witness>(){return complete(irp,BUFFER_SMALL,0);}
    let result={let _lock=Guard::take();(*STATE.0.get()).pop()};
    match result{Ok(Some(w))=>{ptr::copy_nonoverlapping((&w as *const Witness).cast::<u8>(),buffer.cast(),mem::size_of::<Witness>());complete(irp,SUCCESS,mem::size_of::<Witness>())},
        Ok(None)=>complete(irp,EMPTY,0),Err(_)=>complete(irp,NOT_READY,0)}
}
unsafe fn cleanup(){
    STOP.store(true,Ordering::Release);
    for i in 0..4 {if IDS[i]!=0{let status=k::FwpsCalloutUnregisterById0(IDS[i]);if status<0{k::KeBugCheckEx(0xE2,0x47323139,status as k::ULONG_PTR,1,0);}IDS[i]=0;}}
    if PROCESS_NOTIFY {let status=k::PsSetCreateProcessNotifyRoutineEx(Some(process_event),1);if status<0{k::KeBugCheckEx(0xE2,0x47323139,status as k::ULONG_PTR,2,0);}PROCESS_NOTIFY=false;}
    k::ExWaitForRundownProtectionRelease(ptr::addr_of_mut!(RUNDOWN));
    redirect::destroy();
    // No caller/callback can now access ledger. Held process and image refs are released once.
    for o in &mut (*STATE.0.get()).owners {if o.file!=0{k::ObfDereferenceObject(o.file as *mut c_void);}if o.process!=0{k::ObfDereferenceObject(o.process as *mut c_void);}*o=Owner::EMPTY;}
    if LINK_CREATED{let mut n=unicode(LINK.as_ptr());k::IoDeleteSymbolicLink(&mut n);LINK_CREATED=false;}
    if !DEVICE.is_null(){k::IoDeleteDevice(DEVICE);DEVICE=ptr::null_mut();}
}
unsafe extern "C" fn unload(_driver:*mut k::DRIVER_OBJECT){cleanup();}

#[no_mangle]
pub unsafe extern "C" fn DriverEntry(driver:*mut k::DRIVER_OBJECT,_path:*const k::UNICODE_STRING)->i32 {
    if driver.is_null(){return INVALID;}
    ptr::write(ptr::addr_of_mut!(LOCK),0);k::ExInitializeRundownProtection(ptr::addr_of_mut!(RUNDOWN));
    let clock=k::KeQueryPerformanceCounter(ptr::null_mut());
    // LARGE_INTEGER's first eight bytes are QuadPart by WDK definition.
    let session=ptr::read_unaligned((&clock as *const k::LARGE_INTEGER).cast::<u64>());
    (*STATE.0.get()).session=if session==0{1}else{session};
    let status=redirect::initialize();if status<0{return status;}
    let mut name=unicode(DEV.as_ptr());let mut sddl=unicode(SDDL.as_ptr());
    let status=k::WdmlibIoCreateDeviceSecure(driver,0,&mut name,k::FILE_DEVICE_UNKNOWN,k::FILE_DEVICE_SECURE_OPEN,0,&mut sddl,&GUARD_GUID,ptr::addr_of_mut!(DEVICE));
    if status<0{redirect::destroy();return status;}
    for i in 0..(*driver).MajorFunction.len(){(*driver).MajorFunction[i]=Some(dispatch);}
    (*driver).DriverUnload=Some(unload);
    let mut link=unicode(LINK.as_ptr());
    let status=k::IoCreateSymbolicLink(&mut link,&mut name);
    if status<0{cleanup();return status;}LINK_CREATED=true;
    let status=k::PsSetCreateProcessNotifyRoutineEx(Some(process_event),0);
    if status<0{cleanup();return status;}PROCESS_NOTIFY=true;
    for i in 0..4 {
        let mut call:k::FWPS_CALLOUT1=mem::zeroed();
        call.calloutKey=match i {0=>V4_GUID,1=>V6_GUID,2=>AUTH_V4_GUID,_=>AUTH_V6_GUID};
        call.classifyFn=Some(if i<2{classify}else{auth_callback});call.notifyFn=Some(notify);
        let status=k::FwpsCalloutRegister1(DEVICE.cast(),&call,&mut IDS[i]);
        if status<0{cleanup();return status;}
    }
    (*DEVICE).Flags &= !k::DO_DEVICE_INITIALIZING;
    SUCCESS
}
#[panic_handler]
fn panic(_info:&core::panic::PanicInfo)->!{unsafe{k::KeBugCheckEx(0xE2,0x47323139,0,3,0)}}
