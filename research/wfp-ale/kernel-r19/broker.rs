//! Raw application ingress -> owned WFP receipt -> pinned SSH transport.
//! The older unverified local SOCKS route is restricted to non-policy research.
//! No driver/service installer. --serve-admitted-lab is for an independently
//! admitted signed-driver lab ONLY; its name is NOT a verifier of safety gates.
#[allow(dead_code)]#[path="kernel/src/handoff.rs"]mod handoff;
mod transport;
mod policy_plan;
#[cfg(windows)]mod broker_windows;
#[cfg(windows)]mod policy_windows;

#[cfg(windows)]
#[derive(Clone)]
enum Upstream {
    /// No WFP policy activated. Research-only legacy protocol baseline.
    LegacySocks(u16),
    /// Actual SSH TCP socket receives WFP records before connect; Rust SSH
    /// authenticates the pinned server key and the user before app payload.
    VerifiedSsh{
        remote:std::net::SocketAddrV4,
        authority:flowbridge_trusted_ssh_r37::ChannelAuthority
    },
}
#[cfg(windows)]
fn serve(image:&std::path::Path,upstream:Upstream,seconds:u64,activate_policy:bool)->std::io::Result<()> {
 use std::{net::TcpListener,sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering}},time::{Duration,Instant},thread,io::Write};
 use broker_windows::{Device,SelectedImage};
 let selection=SelectedImage::open(image)?;
 let v4=TcpListener::bind("127.0.0.1:0")?;let v6=TcpListener::bind("[::1]:0")?;
 let ports=[v4.local_addr()?.port(),v6.local_addr()?.port()];
 let peer_port=match &upstream{Upstream::LegacySocks(p)=>*p,Upstream::VerifiedSsh{remote,..}=>remote.port()};
 if ports.contains(&peer_port){return Err(std::io::Error::other("upstream_listener_collision"));}
 if activate_policy && !matches!(upstream,Upstream::VerifiedSsh{..}){
     return Err(std::io::Error::other("untrusted_socks_cannot_activate_policy"));
 }
 let plan=policy_plan::Plan::new(selection.wfp_appid(),ports).map_err(|_|std::io::Error::other("policy_plan"))?;
 v4.set_nonblocking(true)?;v6.set_nonblocking(true)?;
 let device=Arc::new(Device::open()?);device.arm(&selection,ports[0],ports[1])?;
 let stop=Arc::new(AtomicBool::new(false));let completed=Arc::new(AtomicUsize::new(0));
 let heartbeat={let d=device.clone();let s=stop.clone();thread::spawn(move||{
  let mut healthy=true;
  while !s.load(Ordering::Acquire){if d.command(handoff::PING,&[]).is_err(){healthy=false;s.store(true,Ordering::Release);break;}thread::sleep(Duration::from_millis(250));}
  let stopped=d.command(handoff::STOP,&[]);if healthy{stopped}else{Err(std::io::Error::other("kernel_lease_lost"))}
 })};
 let policy=if activate_policy{
  // The external native harness must validate signature, exact binary, current
  // VNC, SYSTEM rescue, host protections and rollback BEFORE invoking this mode.
  match unsafe{policy_windows::Installed::activate_admitted(&plan)}{
   Ok(p)=>Some(p),Err(_)=>{stop.store(true,Ordering::Release);let _=heartbeat.join();return Err(std::io::Error::other("policy_activation_failed"));}
  }
 }else{None};
 // Write failure must still stop the kernel lease and join workers/heartbeat.
 let mut output=std::io::stdout();
 let mut error=writeln!(output,"{{\"broker_ready\":true,\"scoped_lab_policy_active\":{},\"native_admission_verified_by_broker\":false,\"g2_pass\":false}}",activate_policy).and_then(|_|output.flush()).err();
 if error.is_some(){stop.store(true,Ordering::Release);}
 let started=Instant::now();let mut workers=Vec::new();
 while !stop.load(Ordering::Acquire)&&started.elapsed()<Duration::from_secs(seconds){
  for listener in [&v4,&v6]{match listener.accept(){
   Ok((client,_))=>{
    if workers.len()>=32{error=Some(std::io::Error::other("connection_cap"));stop.store(true,Ordering::Release);break;}
    let d=device.clone();let s=stop.clone();let done=completed.clone();
    let upstream=upstream.clone();workers.push(thread::spawn(move||{
     let result=(||{
      let received=broker_windows::receive(client)?;
      match upstream {
        Upstream::LegacySocks(p) => {
          let admitted=received.claim_and_connect(&d,p)?;
          admitted.relay(s.clone())?;
        }
        Upstream::VerifiedSsh{remote,authority} => {
          let trusted=received.claim_and_connect_trusted_ssh(&d,remote)?;
          trusted.relay(authority)?;
        }
      }
      done.fetch_add(1,Ordering::AcqRel);Ok::<_,std::io::Error>(())
     })();
     if result.is_err(){s.store(true,Ordering::Release);}result
    }));
   },Err(e)if e.kind()==std::io::ErrorKind::WouldBlock=>{},Err(e)=>{error=Some(e);stop.store(true,Ordering::Release);break;}
  }}thread::sleep(Duration::from_millis(20));
 }
 stop.store(true,Ordering::Release);
 match heartbeat.join(){Ok(Ok(()))=>{},_=>error=Some(std::io::Error::other("kernel_stop_failed"))}
 for worker in workers{match worker.join(){Ok(Ok(()))=>{},_=>error=Some(std::io::Error::other("admission_or_relay_failed"))}}
 drop(v4);drop(v6);
 // Dynamic policy is ONLY a bounded lab aid. The external harness must end all
 // selected clients before this teardown; it is not a crash-persistent barrier.
 if let Some(p)=policy{if p.close().is_err(){error=Some(std::io::Error::other("lab_policy_close_failed"));}}
 let _=writeln!(output,"{{\"completed_admitted_relays\":{},\"g2_pass\":false,\"release_accepted\":false}}",completed.load(Ordering::Acquire));
 if let Some(e)=error{Err(e)}else{Ok(())}
}
fn main(){
 let args:Vec<String>=std::env::args().collect();
 #[cfg(windows)]let result:Result<(),std::io::Error>=(||{
  if args.len()==2&&args[1]=="--reject-unredirected"{
   return broker_windows::ordinary_socket_negative();
  }
  if args.len()==2&&args[1]=="--verify-policy-plan"{
   let selected=broker_windows::SelectedImage::open(&std::env::current_exe()?)?;
   let p=policy_plan::Plan::new(selected.wfp_appid(),[1091,1092])
       .map_err(|_|std::io::Error::other("plan"))?;
   return policy_windows::verify_plan_only(&p)
       .map_err(|_|std::io::Error::other("plan"));
  }
  if args.len()==5&&args[1]=="--serve-research"{
   let port=args[3].parse::<u16>().map_err(|_|std::io::Error::other("port"))?;
   let seconds=args[4].parse::<u64>().map_err(|_|std::io::Error::other("duration"))?;
   if port==0||seconds==0||seconds>300{return Err(std::io::Error::other("arguments"));}
   return serve(std::path::Path::new(&args[2]),Upstream::LegacySocks(port),seconds,false);
  }
  if args.len()==9&&args[1]=="--serve-pinned-ssh-lab"{
   let ip=args[3].parse::<std::net::Ipv4Addr>()
       .map_err(|_|std::io::Error::other("ssh_address"))?;
   let port=args[4].parse::<u16>().map_err(|_|std::io::Error::other("ssh_port"))?;
   let seconds=args[8].parse::<u64>().map_err(|_|std::io::Error::other("duration"))?;
   if ip.is_unspecified()||ip.is_multicast()||port==0||seconds==0||seconds>300{
      return Err(std::io::Error::other("arguments"));
   }
   let authority=flowbridge_trusted_ssh_r37::ChannelAuthority::from_files(
      std::path::Path::new(&args[6]),std::path::Path::new(&args[7]),args[5].clone())?;
   return serve(std::path::Path::new(&args[2]),Upstream::VerifiedSsh{
      remote:std::net::SocketAddrV4::new(ip,port),authority
   },seconds,true);
  }
  // Old --serve-admitted-lab is deliberately disabled. Its NOAUTH local
  // SOCKS listener did not prove SSH peer identity (R33 negative finding).
  Err(std::io::Error::other("arguments_or_untrusted_upstream"))
 })();
 #[cfg(not(windows))]let result:Result<(),std::io::Error>={
  let _=args;Err(std::io::Error::other("windows_required"))
 };
 match result {
  Ok(())=>println!("{{\"ok\":true,\"g2_pass\":false,\"kernel_load_performed_by_broker\":false}}"),
  Err(_)=>{println!("{{\"ok\":false,\"error\":\"research_broker_stopped\",\"g2_pass\":false}}");std::process::exit(2);}
 }
}
