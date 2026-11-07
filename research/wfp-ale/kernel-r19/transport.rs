//! TCP transport after admission. No caller-provided application bytes are used
//! as SOCKS control data. There is deliberately no direct-destination connector.
use std::{io::{self,Read,Write},net::{TcpStream,Shutdown},sync::{Arc,atomic::{AtomicBool,Ordering}},time::{Duration,Instant}};
use crate::handoff::Destination;
fn invalid()->io::Error{io::Error::new(io::ErrorKind::InvalidData,"socks_protocol_rejected")}
pub fn socks_connect(s:&mut TcpStream,d:Destination)->io::Result<()>{
    if !d.valid(){return Err(invalid());}
    s.set_read_timeout(Some(Duration::from_secs(5)))?;s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(&[5,1,0])?;let mut response=[0;2];s.read_exact(&mut response)?;
    if response!=[5,0]{return Err(invalid());}
    let mut req=vec![5,1,0,if d.family==4{1}else{4}];
    req.extend_from_slice(if d.family==4{&d.ip[..4]}else{&d.ip});req.extend_from_slice(&d.port.to_be_bytes());s.write_all(&req)?;
    let mut h=[0;4];s.read_exact(&mut h)?;
    if h[..3]!=[5,0,0]{return Err(invalid());}
    let n=match h[3]{1=>4,4=>16,3=>{let mut n=[0];s.read_exact(&mut n)?;if n[0]==0{return Err(invalid());}n[0] as usize},_=>return Err(invalid())};
    let mut tail=vec![0;n+2];s.read_exact(&mut tail)?;Ok(())
}
fn pump(mut source:TcpStream,mut destination:TcpStream,stop:&AtomicBool)->io::Result<u64>{
    source.set_read_timeout(Some(Duration::from_secs(1)))?;destination.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut data=[0u8;16384];let mut total=0;let mut last=Instant::now();
    loop{
        if stop.load(Ordering::Acquire){return Err(io::Error::new(io::ErrorKind::Interrupted,"relay_stopped"));}
        match source.read(&mut data){
            Ok(0)=>{destination.shutdown(Shutdown::Write)?;return Ok(total);},
            Ok(n)=>{destination.write_all(&data[..n])?;total+=n as u64;last=Instant::now();},
            Err(e) if matches!(e.kind(),io::ErrorKind::TimedOut|io::ErrorKind::WouldBlock)=>{
                if last.elapsed()>Duration::from_secs(30){return Err(io::Error::new(io::ErrorKind::TimedOut,"relay_idle"));}
            },Err(e)=>return Err(e),
        }
    }
}
pub fn relay(client:TcpStream,upstream:TcpStream,stop:Arc<AtomicBool>)->io::Result<(u64,u64)>{
    let a=client.try_clone()?;let b=upstream.try_clone()?;
    std::thread::scope(|scope|{
        let s=&*stop;let first=scope.spawn(move||{let result=pump(a,b,s);if result.is_err(){s.store(true,Ordering::Release);}result});
        let second=pump(upstream,client,&stop);if second.is_err(){stop.store(true,Ordering::Release);}
        let left=first.join().map_err(|_|io::Error::other("relay_thread_failed"))??;
        Ok((left,second?))
    })
}
#[cfg(test)]
mod tests{
    use super::*;use std::net::TcpListener;
    fn dest()->Destination{let mut ip=[0;16];ip[..4].copy_from_slice(&[192,0,2,10]);Destination{family:4,ip,port:443}}
    #[test]fn socks_exact_ipv4_command(){let l=TcpListener::bind("127.0.0.1:0").unwrap();let a=l.local_addr().unwrap();let t=std::thread::spawn(move||{
        let(mut s,_)=l.accept().unwrap();let mut hello=[0;3];s.read_exact(&mut hello).unwrap();assert_eq!(hello,[5,1,0]);s.write_all(&[5,0]).unwrap();
        let mut request=[0;10];s.read_exact(&mut request).unwrap();assert_eq!(request,[5,1,0,1,192,0,2,10,1,187]);s.write_all(&[5,0,0,1,0,0,0,0,0,0]).unwrap();});
        socks_connect(&mut TcpStream::connect(a).unwrap(),dest()).unwrap();t.join().unwrap();}
    #[test]fn denied_socks_never_sends_application_payload(){let l=TcpListener::bind("127.0.0.1:0").unwrap();let a=l.local_addr().unwrap();let t=std::thread::spawn(move||{
        let(mut s,_)=l.accept().unwrap();let mut h=[0;3];s.read_exact(&mut h).unwrap();s.write_all(&[5,0xff]).unwrap();s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();let mut extra=[0;1];assert_eq!(s.read(&mut extra).unwrap(),0);});
        {let mut s=TcpStream::connect(a).unwrap();assert!(socks_connect(&mut s,dest()).is_err());}t.join().unwrap();}
    #[cfg(ssh_integration)]
    #[test]fn actual_openssh_ipv4_ipv6_and_half_close(){
        let port:u16=std::env::var("FB_SSH_SOCKS_PORT").expect("real isolated OpenSSH required").parse().unwrap();
        for ipv6 in [false,true]{
            let origin=TcpListener::bind(if ipv6{"[::1]:0"}else{"127.0.0.1:0"}).unwrap();let address=origin.local_addr().unwrap();
            let server=std::thread::spawn(move||{let(mut c,_)=origin.accept().unwrap();c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut body=Vec::new();c.read_to_end(&mut body).unwrap();assert_eq!(body,b"redirect-relay-half-close");c.write_all(b"ssh-origin-exact-response").unwrap();});
            let listener=TcpListener::bind("127.0.0.1:0").unwrap();let proxy=listener.local_addr().unwrap();
            let handler=std::thread::spawn(move||{let(c,_)=listener.accept().unwrap();let mut upstream=TcpStream::connect((std::net::Ipv4Addr::LOCALHOST,port)).unwrap();
                let mut ip=[0;16];match address.ip(){std::net::IpAddr::V4(v)=>ip[..4].copy_from_slice(&v.octets()),std::net::IpAddr::V6(v)=>ip=v.octets()};
                socks_connect(&mut upstream,Destination{family:if ipv6{6}else{4},port:address.port(),ip}).unwrap();
                relay(c,upstream,Arc::new(AtomicBool::new(false))).unwrap();});
            let mut c=TcpStream::connect(proxy).unwrap();c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();c.write_all(b"redirect-relay-half-close").unwrap();c.shutdown(Shutdown::Write).unwrap();
            let mut reply=Vec::new();c.read_to_end(&mut reply).unwrap();assert_eq!(reply,b"ssh-origin-exact-response");handler.join().unwrap();server.join().unwrap();
        }
        println!("REAL_OPENSSH_TRANSPORT_ONLY_PASS; kernel_redirect_native=false");
    }
}
