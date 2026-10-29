from pathlib import Path
p=Path('tests/windows_safety_filters.cpp');s=p.read_text()
def replace(old,new):
 global s
 assert s.count(old)==1,(old[:80],s.count(old))
 s=s.replace(old,new)
replace('static int connectTCP(','''static bool delivered(SOCKET socket,unsigned milliseconds=700){
    fd_set readable;FD_ZERO(&readable);FD_SET(socket,&readable);
    timeval timeout{static_cast<long>(milliseconds/1000),static_cast<long>((milliseconds%1000)*1000)};
    int ready=select(0,&readable,nullptr,nullptr,&timeout);require(ready>=0,"UDP receive readiness failed");
    if(!ready)return false;char value=0;require(recv(socket,&value,1,0)==1&&value=='x',"Unexpected fixture datagram");return true;
}
static int connectTCP(''')
replace('require(sendUDP(ip,443)==0&&sendUDP(ip,53)==0&&connectTCP(ip,53)==0,"Unfiltered local fixture not reachable");','''require(sendUDP(ip,443)==0&&delivered(quic.value)&&sendUDP(ip,53)==0&&delivered(dnsUDP.value)&&connectTCP(ip,53)==0,"Unfiltered local fixture not reachable");''')
replace('require(quicError==WSAEACCES&&udpError==WSAEACCES&&tcpError==WSAEACCES,"WFP did not deny selected QUIC and direct DNS");','''// UDP send can enqueue successfully before asynchronous WFP authorization.
        // The acceptance criterion is non-delivery to the actual listener.
        require((quicError==0||quicError==WSAEACCES)&&(udpError==0||udpError==WSAEACCES)&&tcpError==WSAEACCES,"Unexpected socket error under WFP policy");
        require(!delivered(quic.value)&&!delivered(dnsUDP.value),"WFP allowed a forbidden UDP datagram to reach the listener");''')
replace('require(sendUDP("127.0.0.1",53)==0,"Loopback DNS stub was blocked");','require(sendUDP("127.0.0.1",53)==0&&delivered(loop.value),"Loopback DNS stub was blocked");')
replace('require(code==0,"Unselected application QUIC was blocked");','require(code==0&&delivered(quic.value),"Unselected application QUIC was blocked");')
replace('require(sendUDP(ip,443)==0&&sendUDP(ip,53)==0&&connectTCP(ip,53)==0,"Dynamic safety filters survived Stop");','require(sendUDP(ip,443)==0&&delivered(quic.value)&&sendUDP(ip,53)==0&&delivered(dnsUDP.value)&&connectTCP(ip,53)==0,"Dynamic safety filters survived Stop");')
p.write_text(s)
print('UDP is now checked at the receiving socket, with baseline/drain, blocked delivery, bypass and restored delivery assertions')
