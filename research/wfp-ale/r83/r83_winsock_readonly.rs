// R83: clean-room, user-mode, read-only negative baseline (Windows x86_64 only).
// Creates ONLY owned UNCONNECTED IPv4/IPv6 TCP sockets; no bind/connect/send,
// WFP filters, drivers, callouts, services, policy changes or CLAIM.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(target_os="windows",target_pointer_width="64")))]
compile_error!("R83 requires Windows x86_64");
#[cfg(all(target_os="windows",target_pointer_width="64"))]
mod probe {
    use std::ffi::c_void;
    use std::mem::{self,MaybeUninit};
    use std::ptr::{null,null_mut};
    type Socket=usize;
    type Handle=isize;
    const INVALID_SOCKET:Socket=!0;
    const SOCKET_ERROR:i32=-1;
    const AF_INET:i32=2;
    const AF_INET6:i32=23;
    const SOCK_STREAM:i32=1;
    const IPPROTO_TCP:i32=6;
    const WSA_FLAG_OVERLAPPED:u32=1;
    const WSA_IO_PENDING:i32=997;
    const WSA_IO_INCOMPLETE:i32=996;
    const WSA_OPERATION_ABORTED:i32=995;
    const WAIT_OBJECT_0:u32=0;
    const WAIT_TIMEOUT:u32=258;
    // Mstcpip.h: _WSAIOW(IOC_VENDOR,220/221).
    const SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS:u32=0x9800_00dc;
    const SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT:u32=0x9800_00dd;
    #[repr(C)]
    struct WsaData {
        version:u16,high_version:u16,max_sockets:u16,max_udp_dg:u16,
        vendor_info:*mut u8,description:[u8;257],system_status:[u8;129],
    }
    #[repr(C)]
    #[derive(Default)]
    struct WsaOverlapped {
        internal:usize,internal_high:usize,offset:u32,offset_high:u32,event:Handle,
    }
    #[link(name="Ws2_32")]
    unsafe extern "system" {
        fn WSAStartup(version:u16,data:*mut WsaData)->i32;
        fn WSACleanup()->i32;
        fn WSASocketW(af:i32,kind:i32,proto:i32,info:*const c_void,group:u32,flags:u32)->Socket;
        fn closesocket(socket:Socket)->i32;
        fn WSAGetLastError()->i32;
        fn WSAIoctl(socket:Socket,code:u32,input:*mut c_void,inlen:u32,
            output:*mut c_void,outlen:u32,returned:*mut u32,
            overlapped:*mut WsaOverlapped,completion:*mut c_void)->i32;
        fn WSAGetOverlappedResult(socket:Socket,overlapped:*mut WsaOverlapped,
            transfer:*mut u32,wait:i32,flags:*mut u32)->i32;
    }
    #[link(name="Kernel32")]
    unsafe extern "system" {
        fn CreateEventW(attributes:*const c_void,manual_reset:i32,
            initial_state:i32,name:*const u16)->Handle;
        fn WaitForSingleObject(handle:Handle,milliseconds:u32)->u32;
        fn CloseHandle(handle:Handle)->i32;
    }
    struct SocketOwner(Socket);
    impl Drop for SocketOwner {
        fn drop(&mut self) { unsafe { closesocket(self.0); } }
    }
    struct EventOwner(Handle);
    impl Drop for EventOwner {
        fn drop(&mut self) { unsafe { CloseHandle(self.0); } }
    }
    struct Winsock;
    impl Winsock {
        fn initialize()->Result<Self,i32> {
            let mut data=MaybeUninit::<WsaData>::uninit();
            let rc=unsafe { WSAStartup(0x0202,data.as_mut_ptr()) };
            if rc==0 { Ok(Self) } else { Err(rc) }
        }
    }
    impl Drop for Winsock {
        fn drop(&mut self) { unsafe { WSACleanup(); } }
    }
    fn query(socket:Socket,family:&'static str,name:&'static str,code:u32)->bool {
        // Stable heap objects survive until terminal overlapped completion.
        let mut output=Box::new([0u8;1024]);
        let mut bytes=Box::new(0u32);
        let event=unsafe { CreateEventW(null(),1,0,null()) };
        if event==0 {
            println!("{family}\t{name}\tEVENT_ERROR\tNO_WFP_PROOF");
            return false;
        }
        let owner=EventOwner(event);
        let mut ov=Box::new(WsaOverlapped { event,..Default::default() });
        let rc=unsafe { WSAIoctl(socket,code,null_mut(),0,
            output.as_mut_ptr().cast(),output.len() as u32,
            &mut *bytes,&mut *ov,null_mut()) };
        if rc==0 {
            println!("{family}\t{name}\tIMMEDIATE_OK\tbytes={}\tNO_WFP_PROOF",*bytes);
            return true;
        }
        if rc!=SOCKET_ERROR {
            println!("{family}\t{name}\tUNKNOWN_RETURN\t{rc}\tNO_WFP_PROOF");
            mem::forget(output); mem::forget(bytes);mem::forget(ov);mem::forget(owner);
            return false;
        }
        let start_error=unsafe { WSAGetLastError() };
        if start_error!=WSA_IO_PENDING {
            println!("{family}\t{name}\tIMMEDIATE_ERROR\t{start_error}\tNO_WFP_PROOF");
            return true;
        }
        // WSA_IO_PENDING and zero immediate bytes never prove missing receipt.
        let wait=unsafe { WaitForSingleObject(event,500) };
        let mut transferred=0u32;
        let mut flags=0u32;
        let done=unsafe { WSAGetOverlappedResult(socket,&mut *ov,
            &mut transferred,0,&mut flags) };
        if done!=0 {
            println!("{family}\t{name}\tOVERLAPPED_OK\tbytes={transferred}\tNO_WFP_PROOF");
            return true;
        }
        let final_error=unsafe { WSAGetLastError() };
        if final_error==WSA_OPERATION_ABORTED {
            println!("{family}\t{name}\tOVERLAPPED_ABORTED\tNO_WFP_PROOF");
            return true;
        }
        // A signaled event, timeout, WSA_IO_INCOMPLETE or parameters error
        // alone is NOT a terminal witness. No buffer/OVERLAPPED reuse.
        println!("{family}\t{name}\tPENDING_OR_UNKNOWN\twait={wait}\terr={final_error}\tNO_WFP_PROOF");
        if wait==WAIT_TIMEOUT || wait==WAIT_OBJECT_0 || final_error==WSA_IO_INCOMPLETE {
            // No conclusion without documented terminal completion.
        }
        // Escrow unresolved IO resources until this short-lived process exits.
        // Only the caller-owned unconnected socket is closed upon function exit.
        mem::forget(output);mem::forget(bytes);mem::forget(ov);mem::forget(owner);
        false
    }
    pub fn run() {
        assert_eq!(mem::size_of::<WsaData>(),408);
        assert_eq!(mem::size_of::<WsaOverlapped>(),32);
        let _winsock=match Winsock::initialize() {
            Ok(v)=>v,
            Err(e)=>{eprintln!("WSAStartup error {e}");std::process::exit(2)}
        };
        for (family,name) in [(AF_INET,"IPv4"),(AF_INET6,"IPv6")] {
            let handle=unsafe { WSASocketW(family,SOCK_STREAM,IPPROTO_TCP,
                null(),0,WSA_FLAG_OVERLAPPED) };
            if handle==INVALID_SOCKET {
                println!("{name}\tCREATE_ERROR\t{}",unsafe { WSAGetLastError() });
                continue;
            }
            let socket=SocketOwner(handle);
            if query(socket.0,name,"RECORDS",SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS) {
                query(socket.0,name,"CONTEXT",SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT);
            } else {
                println!("{name}\tCONTEXT_SKIPPED\tprior_io_unresolved");
            }
        }
    }
}
#[cfg(all(target_os="windows",target_pointer_width="64"))]
fn main(){probe::run();}
