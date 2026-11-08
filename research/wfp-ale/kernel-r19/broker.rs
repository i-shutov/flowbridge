//! Raw application ingress -> owned WFP receipt -> pinned SSH transport.
//! The older unverified local SOCKS route is restricted to non-policy research.
//! No driver/service installer. --serve-admitted-lab is for an independently
//! admitted signed-driver lab ONLY; its name is NOT a verifier of safety gates.
#[allow(dead_code)]#[path="kernel/src/handoff.rs"]mod handoff;
mod transport;
#[cfg(windows)]mod broker_lifecycle;
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
fn revoke(stop:&std::sync::Arc<std::sync::atomic::AtomicBool>,
    notify:&tokio::sync::watch::Sender<bool>) {
    stop.store(true,std::sync::atomic::Ordering::Release);
    notify.send_replace(true);
}

#[cfg(windows)]
fn serve(image:&std::path::Path,upstream:Upstream,seconds:u64,activate_policy:bool)->std::io::Result<()> {
 use std::{net::TcpListener,sync::{Arc,atomic::{AtomicBool,Ordering}},time::{Duration,Instant},thread,io::Write};
 use broker_windows::{Device,SelectedImage};
 use broker_lifecycle::{WorkerPool,WorkerOutcome};
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
 let stop=Arc::new(AtomicBool::new(false));
 // Own, sticky revocation shared with each running verified SSH worker.
 // A new worker after STOP immediately observes true.
 let (revocation_tx,revocation_rx)=tokio::sync::watch::channel(false);
 let heartbeat={let d=device.clone();let s=stop.clone();let notify=revocation_tx.clone();thread::spawn(move||{
  let mut healthy=true;
  while !s.load(Ordering::Acquire){if d.command(handoff::PING,&[]).is_err(){healthy=false;revoke(&s,&notify);break;}thread::sleep(Duration::from_millis(250));}
  let stopped=d.command(handoff::STOP,&[]);
  if stopped.is_err(){revoke(&s,&notify);}
  if healthy{stopped}else{Err(std::io::Error::other("kernel_lease_lost"))}
 })};
 let policy=if activate_policy{
  // The external native harness must validate signature, exact binary, current
  // VNC, SYSTEM rescue, host protections and rollback BEFORE invoking this mode.
  match unsafe{policy_windows::Installed::activate_admitted(&plan)}{
   Ok(p)=>Some(p),Err(_)=>{revoke(&stop,&revocation_tx);let _=heartbeat.join();return Err(std::io::Error::other("policy_activation_failed"));}
  }
 }else{None};
 // Write failure must still stop the kernel lease and join workers/heartbeat.
 let mut output=std::io::stdout();
 let mut error=writeln!(output,"{{\"broker_ready\":true,\"scoped_lab_policy_active\":{},\"native_admission_verified_by_broker\":false,\"g2_pass\":false}}",activate_policy).and_then(|_|output.flush()).err();
 if error.is_some(){revoke(&stop,&revocation_tx);}

 let started=Instant::now();
 // Capacity is reserved only by LIVE workers, not by every connection ever
 // accepted during the session. A rejected local socket is never authority
 // to revoke an unrelated, already authenticated SSH relay.
 let mut workers=WorkerPool::new(32);
 while !stop.load(Ordering::Acquire)&&started.elapsed()<Duration::from_secs(seconds){
  if let Err(e)=workers.poll(){error=Some(e);revoke(&stop,&revocation_tx);break;}
  for listener in [&v4,&v6]{
   if stop.load(Ordering::Acquire){break;}
   match listener.accept(){
    Ok((client,_))=>{
     let d=device.clone();let s=stop.clone();
     let notify=revocation_tx.clone();let worker_revocation=revocation_rx.clone();
     let upstream=upstream.clone();
     match workers.spawn(move||{
      // Ordinary or forged ingress cannot obtain the WFP accepted-socket
      // receipt. Reject ONLY this stream, without global STOP. A selected
      // client with missing/malformed evidence also fails closed per-flow.
      let received=match broker_windows::receive(client){
       Ok(value)=>value,
       Err(_)=>return Ok(WorkerOutcome::IngressRejected),
      };
      // Once an owned WFP receipt exists, any CLAIM/physical-SSH/relay
      // failure revokes the shared kernel lease and every active SSH relay.
      let result=(||->std::io::Result<()>{
       match upstream{
        Upstream::LegacySocks(p)=>{
         let admitted=received.claim_and_connect(&d,p)?;
         admitted.relay(s.clone())?;
        }
        Upstream::VerifiedSsh{remote,authority}=>{
         let trusted=received.claim_and_connect_trusted_ssh(&d,remote)?;
         trusted.relay(authority,worker_revocation)?;
        }
       }
       Ok(())
      })();
      if result.is_err(){revoke(&s,&notify);}
      result.map(|_|WorkerOutcome::Relayed)
     }){
      Ok(_scheduled)=>{}, // false means drop this stream at the active cap
      Err(e)=>{error=Some(e);revoke(&stop,&revocation_tx);break;}
     }
    }
    Err(e)if e.kind()==std::io::ErrorKind::WouldBlock=>{},
    Err(e)=>{error=Some(e);revoke(&stop,&revocation_tx);break;}
   }
  }
  thread::sleep(Duration::from_millis(20));
 }
 revoke(&stop,&revocation_tx);
 match heartbeat.join(){Ok(Ok(()))=>{},_=>error=Some(std::io::Error::other("kernel_stop_failed"))}
 if workers.finish().is_err(){error=Some(std::io::Error::other("admission_or_relay_failed"));}
 drop(v4);drop(v6);
 // Dynamic policy is ONLY a bounded lab aid. The external harness must end all
 // selected clients before this teardown; it is not a crash-persistent barrier.
 if let Some(p)=policy{if p.close().is_err(){error=Some(std::io::Error::other("lab_policy_close_failed"));}}
 let _=writeln!(output,"{{\"completed_admitted_relays\":{},\"rejected_unproven_ingress\":{},\"dropped_at_active_capacity\":{},\"g2_pass\":false,\"release_accepted\":false}}",workers.completed(),workers.rejected_ingress(),workers.dropped_capacity());
 if let Some(e)=error{Err(e)}else{Ok(())}
}
#[cfg(all(test, windows))]
mod broker_revocation_tests {
    use super::*;
    use std::sync::{Arc,atomic::{AtomicBool,Ordering}};
    #[test]
    fn kernel_lease_loss_broadcast_is_sticky() {
        let stop=Arc::new(AtomicBool::new(false));
        let (send,rx)=tokio::sync::watch::channel(false);
        revoke(&stop,&send);
        assert!(stop.load(Ordering::Acquire));
        assert!(*rx.borrow());
        let after=send.subscribe();
        assert!(*after.borrow());
    }
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
