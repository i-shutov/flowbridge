//! Actual inline ALE redirect + one-use broker claim. No BFE filter installer.
//! All state below is private and covered by the existing kernel spin lock.
//! Driver stays unarmed until an observed broker process configures its listeners.
use super::{k,Cell,Guard,STATE,read_at};
use super::handoff::{self as h,Book,Context,Destination,Origin};
use core::{ffi::c_void,ptr,slice};
struct Policy { configured:bool,armed:bool,pid:u64,process:usize,ports:[u16;2],last:u64,len:usize,name:[u8;512],book:Book }
static ROUTE:Cell<Policy>=Cell(core::cell::UnsafeCell::new(Policy{configured:false,armed:false,pid:0,process:0,ports:[0;2],last:0,len:0,name:[0;512],book:Book::new()}));
static mut HANDLE:k::HANDLE=ptr::null_mut();
const TAG:u32=0x33324246;
#[link(name="cng")]
unsafe extern "C" { fn BCryptGenRandom(handle:*mut c_void,buffer:*mut u8,length:u32,flags:u32)->i32; }
unsafe fn now()->u64{let mut stamp=0;k::KeQueryInterruptTimePrecise(&mut stamp)}
unsafe fn lose(){let r=&mut *ROUTE.0.get();r.armed=false;r.book.kill();}
unsafe fn ready(time:u64)->bool{
    let r=&mut *ROUTE.0.get();
    let owner=(*STATE.0.get()).lookup(r.pid);
    if !r.armed || r.book.lost || time<r.last || time-r.last>h::LEASE
        || !matches!(owner,Some((o,_)) if o.process==r.process){lose();return false;}true
}
pub unsafe fn initialize()->i32{
    // PASSIVE_LEVEL DriverEntry only. Never call system-preferred RNG at DISPATCH.
    let mut seed=[0;16];let status=BCryptGenRandom(ptr::null_mut(),seed.as_mut_ptr(),16,2);
    if status<0 || seed==[0;16]{return super::NOT_READY;}
    if !(*ROUTE.0.get()).book.initialize(seed){return super::NOT_READY;}
    k::FwpsRedirectHandleCreate0(&super::GUARD_GUID,0,ptr::addr_of_mut!(HANDLE))
}
pub unsafe fn destroy(){if !HANDLE.is_null(){k::FwpsRedirectHandleDestroy0(HANDLE);HANDLE=ptr::null_mut();}}
pub unsafe fn process_exit(pid:u64){if (*ROUTE.0.get()).pid==pid{lose();}}
fn u16at(b:&[u8],at:usize)->u16{u16::from_le_bytes([b[at],b[at+1]])}
fn u32at(b:&[u8],at:usize)->u32{u32::from_le_bytes([b[at],b[at+1],b[at+2],b[at+3]])}
pub unsafe fn ioctl(code:u32,input:&[u8],caller:k::PEPROCESS)->i32{
    if caller.is_null(){return super::DENIED;}
    let pid=k::PsGetProcessId(caller) as usize as u64;
    let time=now();let _lock=Guard::take();let r=&mut *ROUTE.0.get();
    if code==h::ARM{
        if r.configured || input.len()!=h::ARM_LEN || &input[..4]!=b"FBA3" || input[4..8]!=[1,0,16,2]{return super::INVALID;}
        let n=u32at(input,12) as usize;let p4=u16at(input,8);let p6=u16at(input,10);
        if n==0||n>512||n%2!=0||p4==0||p6==0||pid>u32::MAX as u64
            ||input[16+n..].iter().any(|&b|b!=0){return super::INVALID;}
        let Some((broker,_))=(*STATE.0.get()).lookup(pid) else{return super::DENIED};
        if broker.process!=caller as usize || input[16..16+n]==broker.name[..broker.name_len]{return super::DENIED;}
        r.name[..n].copy_from_slice(&input[16..16+n]);r.len=n;r.pid=pid;r.process=caller as usize;
        r.ports=[p4,p6];r.last=time;r.configured=true;r.armed=true;return super::SUCCESS;
    }
    if !r.configured || r.process!=caller as usize || r.pid!=pid{return super::DENIED;}
    if code==h::STOP{lose();return super::SUCCESS;}
    if code==h::PING{
        if !input.is_empty() || !ready(time){return super::NOT_READY;}
        (*ROUTE.0.get()).last=time;return super::SUCCESS;
    }
    if code==h::CLAIM{
        if input.len()!=h::LEN || !ready(time){return super::DENIED;}
        let mut c=Context::EMPTY;c.0.copy_from_slice(input);
        // Claim is terminal before origin liveness checking. No public receipt minting.
        let Some(c)=(*ROUTE.0.get()).book.take(c,time) else{return super::DENIED};
        let Some((o,generation))=(*STATE.0.get()).lookup(c.number(32)) else{return super::DENIED};
        let selected=&*ROUTE.0.get(); // explicit borrow; the existing spin lock is still held
        if !c.matches_origin(Origin{pid:o.pid,epoch:o.epoch,key:o.start_key,endpoint:c.number(56),generation})
            || o.name[..o.name_len]!=selected.name[..selected.len]{return super::DENIED;}
        return super::SUCCESS;
    }
    super::INVALID
}
unsafe fn block(out:*mut k::FWPS_CLASSIFY_OUT0){(*out).actionType=k::FWP_ACTION_BLOCK;(*out).rights&=!k::FWPS_RIGHT_ACTION_WRITE;}
struct Writable { handle:u64,request:*mut k::FWPS_CONNECT_REQUEST0 }
impl Drop for Writable {fn drop(&mut self){unsafe{
    // WFP requires Apply for every successful writable-data acquisition, even unchanged.
    if !self.request.is_null(){k::FwpsApplyModifiedLayerData0(self.handle,self.request.cast(),0);}
    k::FwpsReleaseClassifyHandle0(self.handle);
}}}
unsafe fn writable(context:*const c_void,filter:*const k::FWPS_FILTER1,out:*mut k::FWPS_CLASSIFY_OUT0)->Option<Writable>{
    if context.is_null()||filter.is_null(){return None;}
    let mut handle=0;if k::FwpsAcquireClassifyHandle0(context.cast_mut(),0,&mut handle)<0{return None;}
    let mut w=Writable{handle,request:ptr::null_mut()};let mut raw=ptr::null_mut();
    if k::FwpsAcquireWritableLayerDataPointer0(handle,(*filter).filterId,0,&mut raw,out)<0{return None;}
    w.request=raw.cast();if w.request.is_null(){return None;}Some(w)
}
fn destination(raw:&[u8],family:u8)->Option<Destination>{
    if raw.len()!=128 || u16at(raw,0)!=(if family==4{2}else{23}){return None;}
    let mut ip=[0;16];if family==4{ip[..4].copy_from_slice(&raw[4..8]);}
    else{if raw[24..28]!=[0;4]{return None;}ip.copy_from_slice(&raw[8..24]);}
    let d=Destination{family,port:u16::from_be_bytes([raw[2],raw[3]]),ip};if d.valid(){Some(d)}else{None}
}
fn local_supported(raw:&[u8],family:u8)->bool{
    if family==4{raw[4..8]==[0;4]||raw[4..8]==[127,0,0,1]}
    else{raw[24..28]==[0;4]&&(raw[8..24]==[0;16]||(raw[8..23]==[0;15]&&raw[23]==1))}
}
pub unsafe fn classify(values:*const k::FWPS_INCOMING_VALUES0,meta:*const k::FWPS_INCOMING_METADATA_VALUES0,
    classify_context:*const c_void,filter:*const k::FWPS_FILTER1,out:*mut k::FWPS_CLASSIFY_OUT0){
    if out.is_null(){return;}
    {let _lock=Guard::take();if !(*ROUTE.0.get()).configured{return;}}
    if values.is_null()||meta.is_null(){block(out);return;}
    let f=&*values;let m=&*meta;
    let (family,index,protocol)=if f.layerId as i32==k::FWPS_LAYER_ALE_CONNECT_REDIRECT_V4{
        (4,k::FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID as usize,k::FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL as usize)
    }else if f.layerId as i32==k::FWPS_LAYER_ALE_CONNECT_REDIRECT_V6{
        (6,k::FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID as usize,k::FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL as usize)
    }else{return;};
    if f.incomingValue.is_null()||index>=f.valueCount as usize||protocol>=f.valueCount as usize{block(out);return;}
    let v=f.incomingValue.add(index).cast::<c_void>();
    if read_at::<i32>(v,k::FB_VALUE_TYPE)!=k::FWP_BYTE_BLOB_TYPE{block(out);return;}
    let blob:*const k::FWP_BYTE_BLOB=read_at(v,k::FB_VALUE_BLOB);
    if blob.is_null()||(*blob).data.is_null()||(*blob).size<2||(*blob).size as usize>514{block(out);return;}
    let mut appid=slice::from_raw_parts((*blob).data,(*blob).size as usize);
    if appid.ends_with(&[0,0]){appid=&appid[..appid.len()-2];}
    {let _lock=Guard::take();let r=&*ROUTE.0.get();if appid!=&r.name[..r.len]{return;}}
    let needed=k::FWPS_METADATA_FIELD_PROCESS_ID|k::FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE;
    let p=f.incomingValue.add(protocol).cast::<c_void>();
    if (*out).rights&k::FWPS_RIGHT_ACTION_WRITE==0||m.currentMetadataValues&needed!=needed
        ||read_at::<i32>(p,k::FB_VALUE_TYPE)!=k::FWP_UINT8||read_at::<u8>(p,k::FB_VALUE_U8)!=6{block(out);return;}
    if m.currentMetadataValues&k::FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE!=0{
        let state=k::FwpsQueryConnectionRedirectState0(m.redirectRecords,HANDLE,ptr::null_mut());
        if state==k::FWPS_CONNECTION_REDIRECTED_BY_SELF{return;}
        if state!=k::FWPS_CONNECTION_NOT_REDIRECTED{block(out);return;}
    }
    let Some(w)=writable(classify_context,filter,out) else{block(out);return;};
    let request=&mut *w.request;
    // Do not overwrite another inspector's local redirect context.
    if !request.localRedirectHandle.is_null()||!request.localRedirectContext.is_null(){block(out);return;}
    let remote=slice::from_raw_parts((&request.remoteAddressAndPort as *const k::SOCKADDR_STORAGE).cast::<u8>(),128);
    let local=slice::from_raw_parts((&request.localAddressAndPort as *const k::SOCKADDR_STORAGE).cast::<u8>(),128);
    let Some(dest)=destination(remote,family) else{block(out);return;};
    // First vertical is loopback proxy only; explicitly bound non-loopback sources reject.
    if !local_supported(local,family){block(out);return;}
    let issue={let _lock=Guard::take();let time=now();
        if !ready(time){None}else{
            let r=&mut *ROUTE.0.get();let port=r.ports[if family==4{0}else{1}];
            let loopback=if family==4{dest.ip[..4]==[127,0,0,1]}else{dest.ip[..15]==[0;15]&&dest.ip[15]==1};
            if loopback&&dest.port==port{None}else{
                (*STATE.0.get()).lookup(m.processId).and_then(|(o,generation)|{
                    if &o.name[..o.name_len]!=appid{return None;}
                    let origin=Origin{pid:o.pid,epoch:o.epoch,key:o.start_key,endpoint:m.transportEndpointHandle,generation};
                    r.book.issue(origin,dest,time).map(|c|(c,r.pid as u32,port))
                })
            }
        }
    };
    let Some((context,broker,port))=issue else{block(out);return;};
    let memory=k::ExAllocatePool2(k::FB_NON_PAGED as u64,h::LEN as k::SIZE_T,TAG);
    if memory.is_null(){let _lock=Guard::take();(*ROUTE.0.get()).book.retire(context);block(out);return;}
    ptr::copy_nonoverlapping(context.0.as_ptr(),memory.cast::<u8>(),h::LEN);
    let mut target=[0u8;128];target[..2].copy_from_slice(&(if family==4{2u16}else{23u16}).to_le_bytes());
    target[2..4].copy_from_slice(&port.to_be_bytes());if family==4{target[4..8].copy_from_slice(&[127,0,0,1]);}else{target[23]=1;}
    ptr::copy_nonoverlapping(target.as_ptr(),(&mut request.remoteAddressAndPort as *mut k::SOCKADDR_STORAGE).cast(),128);
    request.localRedirectTargetPID=broker;request.localRedirectHandle=HANDLE;
    request.localRedirectContext=memory;request.localRedirectContextSize=h::LEN as k::SIZE_T;
    // Ownership of nonpaged context transfers to WFP on Apply (Windows 8+).
    (*out).actionType=k::FWP_ACTION_PERMIT;(*out).rights|=k::FWPS_RIGHT_ACTION_WRITE;
    drop(w); // Apply exactly once, then release classify handle. No direct-connect branch.
}
