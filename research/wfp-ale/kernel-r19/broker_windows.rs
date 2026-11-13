//! Accepted-socket-bound WFP handoff. Received owns the exact accepted stream;
//! neither context nor redirect records can be detached or replaced by callers.
use std::{ffi::c_void,fs::File,io,mem,net::{TcpStream,TcpListener},os::windows::{io::{AsRawSocket,FromRawSocket,AsRawHandle},fs::OpenOptionsExt},path::{Path,Component,Prefix},ptr,sync::{Arc,atomic::AtomicBool}};
use crate::handoff::{self as h,Context};
use crate::policy_plan::Plan;
const QUERY_RECORDS:u32=0x980000dc;const QUERY_CONTEXT:u32=0x980000dd;const SET_RECORDS:u32=0x980000de;
const CAP:usize=65536;
fn fail()->io::Error{io::Error::new(io::ErrorKind::PermissionDenied,"native_handoff_rejected")}
#[repr(C)]struct Blob{size:u32,data:*mut u8}
#[repr(C)]struct SockAddr{family:u16,port:u16,ip:[u8;4],zero:[u8;8]}
#[repr(C)]struct FdSet{count:u32,sockets:[usize;64]}
#[repr(C)]struct TimeVal{seconds:i32,micros:i32}
#[link(name="ws2_32")]unsafe extern "system"{
 fn WSAIoctl(s:usize,code:u32,input:*const c_void,insize:u32,out:*mut c_void,outsize:u32,count:*mut u32,ov:*mut c_void,completion:*mut c_void)->i32;
 fn WSAGetLastError()->i32;fn socket(family:i32,kind:i32,protocol:i32)->usize;fn closesocket(s:usize)->i32;
 fn connect(s:usize,addr:*const c_void,len:i32)->i32;fn ioctlsocket(s:usize,command:i32,arg:*mut u32)->i32;
 fn select(n:i32,read:*mut FdSet,write:*mut FdSet,except:*mut FdSet,time:*const TimeVal)->i32;
 fn getsockopt(s:usize,level:i32,name:i32,value:*mut u8,len:*mut i32)->i32;
}
#[link(name="kernel32")]unsafe extern "system"{
 fn DeviceIoControl(handle:*mut c_void,code:u32,input:*const c_void,insize:u32,out:*mut c_void,outsize:u32,count:*mut u32,ov:*mut c_void)->i32;
 fn GetFinalPathNameByHandleW(handle:*mut c_void,path:*mut u16,size:u32,flags:u32)->u32;
}
#[link(name="fwpuclnt")]unsafe extern "system"{
 fn FwpmGetAppIdFromFileName0(path:*const u16,blob:*mut *mut Blob)->u32;
 fn FwpmFreeMemory0(memory:*mut *mut c_void);
}
/// Retains the selected file open without write/delete sharing throughout the
/// lab run. This is NOT the originating process image-section identity.
pub struct SelectedImage{_file:File,appid:Vec<u8>}
impl SelectedImage{
 pub fn open(path:&Path)->io::Result<Self>{
  if !path.is_absolute()||!matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_))){return Err(fail());}
  let text=path.to_str().ok_or_else(fail)?;
  if text[2..].contains(':')||text.contains('\0'){return Err(fail());}
  let file=File::options().read(true).share_mode(1).open(path)?;
  let mut name=vec![0u16;32768];let n=unsafe{GetFinalPathNameByHandleW(file.as_raw_handle(),name.as_mut_ptr(),name.len() as u32,0)} as usize;
  if n==0||n>=name.len(){return Err(fail());}
  let mut name=String::from_utf16(&name[..n]).map_err(|_|fail())?;
  if !name.starts_with(r"\\?\")||name.as_bytes().get(5)!=Some(&b':'){return Err(fail());}name.drain(..4);
  let wide:Vec<u16>=name.encode_utf16().chain(Some(0)).collect();let mut raw:*mut Blob=ptr::null_mut();
  let status=unsafe{FwpmGetAppIdFromFileName0(wide.as_ptr(),&mut raw)};
  let result=if status!=0||raw.is_null(){Err(fail())}else{unsafe{
   let b=&*raw;if b.data.is_null()||b.size<4||b.size>514||b.size%2!=0{Err(fail())}else{
    let bytes=std::slice::from_raw_parts(b.data,b.size as usize).to_vec();
    if !bytes.ends_with(&[0,0])||bytes[..bytes.len()-2].chunks_exact(2).any(|v|v==[0,0]){Err(fail())}else{Ok(bytes)}
   }
  }};
  if !raw.is_null(){unsafe{let mut p=raw.cast::<c_void>();FwpmFreeMemory0(&mut p);}}
  Ok(Self{_file:file,appid:result?})
 }
 pub fn wfp_appid(&self)->&[u8]{&self.appid}
 fn kernel_name(&self)->&[u8]{&self.appid[..self.appid.len()-2]}
}
pub struct Device(File);
impl Device{
 pub fn open()->io::Result<Self>{Ok(Self(File::options().read(true).write(true).open(r"\\.\FlowBridgeG2WitnessR19")?))}
 pub fn command(&self,code:u32,data:&[u8])->io::Result<()>{
  if !matches!(code,h::ARM|h::CLAIM|h::PING|h::STOP){return Err(fail());}
  let mut n=0;let ok=unsafe{DeviceIoControl(self.0.as_raw_handle(),code,data.as_ptr().cast(),data.len() as u32,ptr::null_mut(),0,&mut n,ptr::null_mut())};
  if ok==0||n!=0{Err(fail())}else{Ok(())}
 }
 pub fn arm(&self,image:&SelectedImage,plan:&Plan,port4:u16,port6:u16)->io::Result<()>{
  // BFE-selected A and ARM-selected B must never silently diverge.
  if !plan.arm_matches(image.wfp_appid(),[port4,port6]){return Err(fail());}
  let appid=image.kernel_name();if port4==0||port6==0{return Err(fail());}
  let mut data=[0u8;h::ARM_LEN];data[..8].copy_from_slice(b"FBA3\x01\x00\x10\x02");
  data[8..10].copy_from_slice(&port4.to_le_bytes());data[10..12].copy_from_slice(&port6.to_le_bytes());
  data[12..16].copy_from_slice(&(appid.len() as u32).to_le_bytes());data[16..16+appid.len()].copy_from_slice(appid);self.command(h::ARM,&data)
 }
}
fn query(s:&TcpStream,code:u32,capacity:usize)->io::Result<Vec<u8>>{
 let mut result=vec![0u8;capacity];let mut n=0;let status=unsafe{WSAIoctl(s.as_raw_socket() as usize,code,ptr::null(),0,result.as_mut_ptr().cast(),capacity as u32,&mut n,ptr::null_mut(),ptr::null_mut())};
 if status!=0||n==0||n as usize>capacity{return Err(fail());}result.truncate(n as usize);Ok(result)
}
pub struct Received{accepted:TcpStream,context:Context,records:Vec<u8>}
pub struct Admitted{accepted:TcpStream,upstream:TcpStream,destination:h::Destination}
pub fn receive(accepted:TcpStream)->io::Result<Received>{
 accepted.peer_addr()?;let records=query(&accepted,QUERY_RECORDS,CAP)?;let bytes=query(&accepted,QUERY_CONTEXT,h::LEN)?;
 let context=Context::parse(&bytes).ok_or_else(fail)?;Ok(Received{accepted,context,records})
}
struct Raw(usize);impl Drop for Raw{fn drop(&mut self){if self.0!=usize::MAX{unsafe{closesocket(self.0);}}}}
impl Received{
 pub fn claim_and_connect(self,device:&Device,port:u16)->io::Result<Admitted>{
  if port==0{return Err(fail());}
  device.command(h::CLAIM,&self.context.0)?;
  let s=Raw(unsafe{socket(2,1,6)});if s.0==usize::MAX{return Err(fail());}
  let mut n=0;let status=unsafe{WSAIoctl(s.0,SET_RECORDS,self.records.as_ptr().cast(),self.records.len() as u32,ptr::null_mut(),0,&mut n,ptr::null_mut(),ptr::null_mut())};
  if status!=0{return Err(fail());}
  let mut one=1u32;if unsafe{ioctlsocket(s.0,0x8004667eu32 as i32,&mut one)}!=0{return Err(fail());}
  let address=SockAddr{family:2,port:port.to_be(),ip:[127,0,0,1],zero:[0;8]};
  if unsafe{connect(s.0,(&address as *const SockAddr).cast(),mem::size_of::<SockAddr>() as i32)}!=0{
   if unsafe{WSAGetLastError()}!=10035{return Err(fail());}
   let mut write=FdSet{count:1,sockets:[0;64]};write.sockets[0]=s.0;let mut except=FdSet{count:1,sockets:[0;64]};except.sockets[0]=s.0;
   if unsafe{select(0,ptr::null_mut(),&mut write,&mut except,&TimeVal{seconds:5,micros:0})}<=0{return Err(fail());}
   let mut error=0i32;let mut size=4;if unsafe{getsockopt(s.0,0xffff,0x1007,(&mut error as *mut i32).cast(),&mut size)}!=0||error!=0{return Err(fail());}
  }
  let mut zero=0u32;if unsafe{ioctlsocket(s.0,0x8004667eu32 as i32,&mut zero)}!=0{return Err(fail());}
  let raw=s.0;mem::forget(s);
  Ok(Admitted{accepted:self.accepted,upstream:unsafe{TcpStream::from_raw_socket(raw as _)},destination:self.context.destination()})
 }
}
impl Admitted{
 pub fn relay(mut self,stop:Arc<AtomicBool>)->io::Result<(u64,u64)>{
  crate::transport::socks_connect(&mut self.upstream,self.destination)?;
  crate::transport::relay(self.accepted,self.upstream,stop)
 }
}
/// R37: created only from an actual socket-owned WFP receipt after terminal
/// kernel CLAIM, never from a caller-constructed destination or SOCKS reply.
/// The physical SSH TCP socket already received SIO_SET_WFP redirect records
/// before connect; it is consumed by the pinned-host-key Russh client.
pub struct TrustedSshRelay {
    accepted: TcpStream,
    physical_ssh: TcpStream,
    destination: h::Destination,
}

impl Received {
    /// IPv4 SSH server socket only in R37. Original IPv4/IPv6 destination is
    /// still sent inside SSH channel_open_direct_tcpip after authentication.
    pub fn claim_and_connect_trusted_ssh(
        self,
        device: &Device,
        remote: std::net::SocketAddrV4,
    ) -> io::Result<TrustedSshRelay> {
        if remote.port()==0 || remote.ip().is_unspecified() || remote.ip().is_multicast(){
            return Err(fail());
        }
        // A malformed/missing foreign context fails receive() before this.
        // CLAIM is terminal even when the trusted SSH TCP setup subsequently
        // fails: the ticket cannot be replayed against a different upstream.
        device.command(h::CLAIM, &self.context.0)?;
        let s=Raw(unsafe{socket(2,1,6)});
        if s.0==usize::MAX {return Err(fail());}
        let mut n=0;
        let status=unsafe{WSAIoctl(s.0,SET_RECORDS,self.records.as_ptr().cast(),
            self.records.len() as u32,ptr::null_mut(),0,&mut n,ptr::null_mut(),ptr::null_mut())};
        if status!=0{return Err(fail());}
        let mut one=1u32;
        if unsafe{ioctlsocket(s.0,0x8004667eu32 as i32,&mut one)}!=0{return Err(fail());}
        let address=SockAddr{family:2,port:remote.port().to_be(),
            ip:remote.ip().octets(),zero:[0;8]};
        if unsafe{connect(s.0,(&address as *const SockAddr).cast(),
            mem::size_of::<SockAddr>() as i32)}!=0{
            if unsafe{WSAGetLastError()}!=10035{return Err(fail());}
            let mut write=FdSet{count:1,sockets:[0;64]};write.sockets[0]=s.0;
            let mut except=FdSet{count:1,sockets:[0;64]};except.sockets[0]=s.0;
            if unsafe{select(0,ptr::null_mut(),&mut write,&mut except,
                &TimeVal{seconds:5,micros:0})}<=0{return Err(fail());}
            let mut error=0i32;let mut size=4;
            if unsafe{getsockopt(s.0,0xffff,0x1007,(&mut error as *mut i32).cast(),
                &mut size)}!=0 || error!=0 {return Err(fail());}
        }
        let mut zero=0u32;
        if unsafe{ioctlsocket(s.0,0x8004667eu32 as i32,&mut zero)}!=0{return Err(fail());}
        let raw=s.0;mem::forget(s);
        Ok(TrustedSshRelay{
            accepted:self.accepted,
            physical_ssh:unsafe{TcpStream::from_raw_socket(raw as _)},
            destination:self.context.destination(),
        })
    }
}

impl TrustedSshRelay {
    /// Rust SSH owns the physical WFP-record-tagged TCP socket from this point.
    /// No local SOCKS listener exists in the trusted path.
    pub fn relay(self, authority:flowbridge_trusted_ssh_r37::ChannelAuthority,
        revocation:tokio::sync::watch::Receiver<bool>)
        -> io::Result<(u64,u64)> {
        let destination=if self.destination.family==4{
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                self.destination.ip[0],self.destination.ip[1],
                self.destination.ip[2],self.destination.ip[3]))
        }else{
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(self.destination.ip))
        };
        let runtime=tokio::runtime::Builder::new_current_thread()
            .enable_all().build()?;
        runtime.block_on(flowbridge_trusted_ssh_r37::relay_over_pinned_ssh(
            self.accepted,self.physical_ssh,destination,
            self.destination.port,authority,revocation))
    }
}

pub fn ordinary_socket_negative()->io::Result<()>{
 for ipv6 in [false,true]{let listener=TcpListener::bind(if ipv6{"[::1]:0"}else{"127.0.0.1:0"})?;
  let a=TcpStream::connect(listener.local_addr()?)?;let(b,_)=listener.accept()?;
  if receive(a).is_ok()||receive(b).is_ok(){return Err(fail());}
 }Ok(())
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn ordinary_socket_never_reaches_claim_or_connect(){ordinary_socket_negative().unwrap();}
 #[test]fn selection_uses_actual_native_appid_without_export(){let image=SelectedImage::open(&std::env::current_exe().unwrap()).unwrap();assert!(image.wfp_appid().ends_with(&[0,0]));assert!(!image.kernel_name().is_empty());}
 #[test]fn selection_rejects_unc_and_relative_before_file_open(){for p in [r"\\server\share\app.exe",r"C:app.exe",r"app.exe",r"C:\app.exe:stream"]{assert!(SelectedImage::open(Path::new(p)).is_err());}}
}
