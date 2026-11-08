//! Isolated user-mode SSH transport lab, never a G2 driver acceptance test.
use std::{io::{self, Write},net::{IpAddr,SocketAddr,TcpListener,TcpStream},path::Path,time::Duration};
use flowbridge_trusted_ssh_r37::{ChannelAuthority,relay_over_pinned_ssh};

fn invalid() -> io::Error { io::Error::new(io::ErrorKind::InvalidInput,"r37_arguments") }

#[tokio::main]
async fn main() {
    let result=run().await;
    match result {
        Ok((up,down)) => println!("{{\"ok\":true,\"bytes_forwarded\":{},\"bytes_returned\":{},\"kernel_redirect_executed\":false,\"g2_pass\":false}}",up,down),
        Err(_) => {println!("{{\"ok\":false,\"error\":\"trusted_ssh_lab_rejected\",\"g2_pass\":false}}");std::process::exit(2);}
    }
}

async fn run() -> io::Result<(u64,u64)> {
    let args:Vec<String>=std::env::args().collect();
    // No credentials or destination are accepted from a client socket.
    if args.len()!=11 || args[1]!="--isolated-transport-lab" || args[2]!="R37_NO_KERNEL" {return Err(invalid());}
    let listen:u16=args[3].parse().map_err(|_|invalid())?;
    let ssh_ip:IpAddr=args[4].parse().map_err(|_|invalid())?;
    let ssh_port:u16=args[5].parse().map_err(|_|invalid())?;
    let dest:IpAddr=args[9].parse().map_err(|_|invalid())?;
    let dest_port:u16=args[10].parse().map_err(|_|invalid())?;
    if listen==0||ssh_port==0||dest_port==0 {return Err(invalid());}
    let authority=ChannelAuthority::from_files(Path::new(&args[7]),Path::new(&args[8]),args[6].clone())?;
    let listener=TcpListener::bind(("127.0.0.1",listen))?;
    println!("R37_TRANSPORT_READY");io::stdout().flush()?;
    let (client,_)=listener.accept()?;
    let ssh=TcpStream::connect_timeout(&SocketAddr::new(ssh_ip,ssh_port),Duration::from_secs(5))?;
    // Transport-only lab has no kernel owner; keep an explicit live sender.
    // In the Windows broker the sender is driven by actual PING/STOP health.
    let (_keepalive,revocation)=tokio::sync::watch::channel(false);
    relay_over_pinned_ssh(client,ssh,dest,dest_port,authority,revocation).await
}
