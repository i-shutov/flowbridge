//! Standalone research broker. The accepted stream is raw application traffic,
//! NOT a SOCKS client. A kernel-attested destination drives the SOCKS handshake.
//! No install/load/filter code, no direct fallback, no user-provided receipts.
#[allow(dead_code)]#[path="kernel/src/handoff.rs"]mod handoff;
mod transport;
#[cfg(windows)]mod broker_windows;
#[cfg(windows)]fn serve(image:&std::path::Path,ssh_port:u16,seconds:u64)->std::io::Result<()>{
    use std::{net::TcpListener,sync::{Arc,atomic::{AtomicBool,Ordering}},time::{Duration,Instant},thread};
    use broker_windows::Device;
    let v4=TcpListener::bind("127.0.0.1:0")?;let v6=TcpListener::bind("[::1]:0")?;
    v4.set_nonblocking(true)?;v6.set_nonblocking(true)?;
    let device=Arc::new(Device::open()?);device.arm(image,v4.local_addr()?.port(),v6.local_addr()?.port())?;
    let stop=Arc::new(AtomicBool::new(false));let started=Instant::now();
    let heartbeat={let d=device.clone();let s=stop.clone();thread::spawn(move||{
        while !s.load(Ordering::Acquire){if d.command(handoff::PING,&[]).is_err(){s.store(true,Ordering::Release);break;}thread::sleep(Duration::from_millis(250));}
        let _=d.command(handoff::STOP,&[]);
    })};
    let mut workers=Vec::new();let mut error=None;
    while !stop.load(Ordering::Acquire)&&started.elapsed()<Duration::from_secs(seconds){
        for listener in [&v4,&v6]{match listener.accept(){
            Ok((client,_))=>{
                if workers.len()>=32{error=Some(std::io::Error::other("connection_cap"));stop.store(true,Ordering::Release);break;}
                let d=device.clone();let s=stop.clone();workers.push(thread::spawn(move||{
                    let result=(||{let received=broker_windows::receive(&client)?;
                        let(mut upstream,dest)=received.claim_and_connect(&d,ssh_port)?;
                        transport::socks_connect(&mut upstream,dest)?;transport::relay(client,upstream,s.clone())?;Ok::<_,std::io::Error>(())})();
                    if result.is_err(){s.store(true,Ordering::Release);}result
                }));
            },Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{},Err(e)=>{error=Some(e);stop.store(true,Ordering::Release);break;}
        }}thread::sleep(Duration::from_millis(20));
    }
    if stop.load(Ordering::Acquire)&&error.is_none(){error=Some(std::io::Error::other("broker_health_lost"));}
    stop.store(true,Ordering::Release);let _=heartbeat.join();
    for worker in workers{match worker.join(){Ok(Ok(()))=>{},_=>{error=Some(std::io::Error::other("admission_or_relay_failed"));}}}
    if let Some(e)=error{Err(e)}else{Ok(())}
}
fn main(){
    let args:Vec<String>=std::env::args().collect();
    #[cfg(windows)]let result=if args.len()==2&&args[1]=="--reject-unredirected"{broker_windows::ordinary_socket_negative()}
    else if args.len()==5&&args[1]=="--serve-research"{
        let port=args[3].parse::<u16>();let seconds=args[4].parse::<u64>();
        match(port,seconds){(Ok(p),Ok(s)) if p>0&&s>0&&s<=300=>serve(std::path::Path::new(&args[2]),p,s),_=>Err(std::io::Error::other("arguments"))}
    }else{Err(std::io::Error::other("arguments"))};
    #[cfg(not(windows))]let result:Result<(),std::io::Error>={let _=args;Err(std::io::Error::other("windows_required"))};
    match result{Ok(())=>println!("{{\"ok\":true,\"g2_pass\":false,\"kernel_load_performed_by_broker\":false}}"),
        Err(_)=>{println!("{{\"ok\":false,\"error\":\"research_broker_stopped\",\"g2_pass\":false}}");std::process::exit(2);}}
}
