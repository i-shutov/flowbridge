//! User-mode Windows adapter. QUERY on the actual accepted socket; SET on the
//! newly created outbound socket BEFORE connect. Only fixed loopback SOCKS next hop.
use std::{ffi::c_void,fs::File,io,mem,net::{TcpStream,TcpListener,SocketAddrV4,Ipv4Addr},os::windows::io::{AsRawSocket,FromRawSocket,AsRawHandle},path::Path,ptr};
use crate::handoff::{self as h,Context};
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
pub struct Device(File);
impl Device{
    pub fn open()->io::Result<Self>{Ok(Self(File::options().read(true).write(true).open(r"\\.\FlowBridgeG2WitnessR19")?))}
    pub fn command(&self,code:u32,data:&[u8])->io::Result<()>{let mut n=0;
        let ok=unsafe{DeviceIoControl(self.0.as_raw_handle(),code,data.as_ptr().cast(),data.len() as u32,ptr::null_mut(),0,&mut n,ptr::null_mut())};
        if ok==0||n!=0{Err(fail())}else{Ok(())}}
    pub fn arm(&self,path:&Path,port4:u16,port6:u16)->io::Result<()>{
        let appid=appid(path)?;let mut data=[0u8;h::ARM_LEN];data[..8].copy_from_slice(b"FBA3\x01\x00\x10\x02");
        data[8..10].copy_from_slice(&port4.to_le_bytes());data[10..12].copy_from_slice(&port6.to_le_bytes());
        data[12..16].copy_from_slice(&(appid.len() as u32).to_le_bytes());data[16..16+appid.len()].copy_from_slice(&appid);self.command(h::ARM,&data)
    }
}
fn appid(path:&Path)->io::Result<Vec<u8>>{
    let file=File::open(path)?;let mut name=vec![0u16;32768];let n=unsafe{GetFinalPathNameByHandleW(file.as_raw_handle(),name.as_mut_ptr(),name.len() as u32,0)} as usize;
    if n==0||n>=name.len(){return Err(fail());}
    let mut name=String::from_utf16(&name[..n]).map_err(|_|fail())?;
    if !name.starts_with(r"\\?\")||name.as_bytes().get(5)!=Some(&b':'){return Err(fail());}name.drain(..4);
    let wide:Vec<u16>=name.encode_utf16().chain(Some(0)).collect();let mut raw:*mut Blob=ptr::null_mut();
    let status=unsafe{FwpmGetAppIdFromFileName0(wide.as_ptr(),&mut raw)};
    let result=if status!=0||raw.is_null(){Err(fail())}else{unsafe{
        let b=&*raw;if b.data.is_null()||b.size<2||b.size>514||b.size%2!=0{Err(fail())}else{
            let mut bytes=std::slice::from_raw_parts(b.data,b.size as usize).to_vec();if bytes.ends_with(&[0,0]){bytes.truncate(bytes.len()-2);}
            if bytes.is_empty()||bytes.len()>512{Err(fail())}else{Ok(bytes)}
        }
    }};
    if !raw.is_null(){unsafe{let mut p=raw.cast::<c_void>();FwpmFreeMemory0(&mut p);}}
    result
}
fn query(s:&TcpStream,code:u32,capacity:usize)->io::Result<Vec<u8>>{
    let mut result=vec![0u8;capacity];let mut n=0;let status=unsafe{WSAIoctl(s.as_raw_socket() as usize,code,ptr::null(),0,result.as_mut_ptr().cast(),capacity as u32,&mut n,ptr::null_mut(),ptr::null_mut())};
    if status!=0||n==0||n as usize>capacity{return Err(fail());}result.truncate(n as usize);Ok(result)
}
pub struct Received{pub context:Context,records:Vec<u8>}
pub fn receive(s:&TcpStream)->io::Result<Received>{
    s.peer_addr()?;let records=query(s,QUERY_RECORDS,CAP)?;let bytes=query(s,QUERY_CONTEXT,h::LEN)?;
    let context=Context::parse(&bytes).ok_or_else(fail)?;Ok(Received{context,records})
}
struct Raw(usize);impl Drop for Raw{fn drop(&mut self){if self.0!=usize::MAX{unsafe{closesocket(self.0);}}}}
impl Received{
    pub fn claim_and_connect(self,device:&Device,port:u16)->io::Result<(TcpStream,h::Destination)>{
        if port==0{return Err(fail());}
        device.command(h::CLAIM,&self.context.0)?; // after both queries, before creating any outbound socket
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
        let raw=s.0;mem::forget(s);Ok((unsafe{TcpStream::from_raw_socket(raw as _)},self.context.destination()))
    }
}
pub fn ordinary_socket_negative()->io::Result<()>{
    for family6 in [false,true]{let listener=TcpListener::bind(if family6{"[::1]:0"}else{"127.0.0.1:0"})?;
        let a=TcpStream::connect(listener.local_addr()?)?;let(b,_)=listener.accept()?;
        if receive(&a).is_ok()||receive(&b).is_ok(){return Err(fail());}
    }Ok(())
}
