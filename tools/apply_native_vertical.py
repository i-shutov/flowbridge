from pathlib import Path

def edit(path,old,new):
    p=Path(path);s=p.read_text(encoding='utf-8')
    if s.count(old)!=1:raise RuntimeError(f'{path}: match count {s.count(old)}')
    p.write_text(s.replace(old,new),encoding='utf-8')

edit('native/macos/Extension/DNSProxyProvider.swift',
 'protocolConfiguration.providerConfiguration?["session_id"]', 'options?["session_id"]')
p='crates/flowbridge-ffi/src/native_dns.rs'
edit(p,'''                    let bound = async {
                        let udp = tokio::net::UdpSocket::bind(listen).await?;
                        let address = udp.local_addr()?;
                        let tcp = tokio::net::TcpListener::bind(address).await?;
                        Ok::<_, io::Error>((udp, tcp, address))
                    }
                    .await;''','''                    let bound = bind_pair(listen).await;''')
edit(p,'impl Drop for Server {',r'''async fn bind_pair(listen: std::net::SocketAddr) -> io::Result<(tokio::net::UdpSocket, tokio::net::TcpListener, std::net::SocketAddr)> {
    for _ in 0..16 {
        // Reserve TCP first: UDP's ephemeral allocator does not know about TCP
        // listeners or TIME_WAIT. A port-zero request may choose another pair;
        // an explicit port is never silently changed.
        let tcp = tokio::net::TcpListener::bind(listen).await?;
        let address = tcp.local_addr()?;
        match tokio::net::UdpSocket::bind(address).await {
            Ok(udp) => return Ok((udp,tcp,address)),
            Err(error) if listen.port()==0 && error.kind()==io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse,"No shared TCP/UDP ephemeral port available after 16 attempts"))
}
impl Drop for Server {''')
edit(p,'    #[test]\n    fn malformed_wire_never_panics()',r'''    #[tokio::test]
    async fn paired_ephemeral_port_and_explicit_conflict_are_distinct() {
        for _ in 0..32 {
            let (udp,tcp,address)=bind_pair("127.0.0.1:0".parse().unwrap()).await.unwrap();
            assert_ne!(address.port(),0);
            assert_eq!(udp.local_addr().unwrap(),address);
            assert_eq!(tcp.local_addr().unwrap(),address);
            assert_eq!(bind_pair(address).await.unwrap_err().kind(),io::ErrorKind::AddrInUse);
        }
    }
    #[test]
    fn malformed_wire_never_panics()''')
print('DNS provider start options and bounded port-pair reservation corrected')
