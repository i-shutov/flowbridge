#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include "../native/windows/native_ipc.hpp"
#include "../native/windows/wfp/safety_filters.hpp"
static void require(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
struct Socket {SOCKET value=INVALID_SOCKET;~Socket(){if(value!=INVALID_SOCKET)closesocket(value);} };
static sockaddr_in endpoint(const std::string& ip,unsigned short port){sockaddr_in out{};out.sin_family=AF_INET;out.sin_port=htons(port);require(InetPtonA(AF_INET,ip.c_str(),&out.sin_addr)==1,"Invalid fixture address");return out;}
static std::string localIP(){
    ULONG size=16384;std::vector<unsigned char> bytes(size);
    auto* first=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(bytes.data());
    ULONG result=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,first,&size);
    if(result==ERROR_BUFFER_OVERFLOW){bytes.resize(size);first=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(bytes.data());result=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,first,&size);}
    require(result==NO_ERROR,"Cannot enumerate disposable runner interfaces");
    for(auto* adapter=first;adapter;adapter=adapter->Next)if(adapter->OperStatus==IfOperStatusUp&&adapter->IfType!=IF_TYPE_SOFTWARE_LOOPBACK)
        for(auto* address=adapter->FirstUnicastAddress;address;address=address->Next)if(address->Address.lpSockaddr->sa_family==AF_INET){
            auto* v4=reinterpret_cast<sockaddr_in*>(address->Address.lpSockaddr);char text[INET_ADDRSTRLEN]{};
            if(InetNtopA(AF_INET,&v4->sin_addr,text,sizeof(text))&&ntohl(v4->sin_addr.s_addr)!=0)return text;
        }
    throw std::runtime_error("No non-loopback local IPv4 fixture interface");
}
static int sendUDP(const std::string& ip,unsigned short port){
    Socket socket;socket.value=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);require(socket.value!=INVALID_SOCKET,"UDP socket failed");
    auto target=endpoint(ip,port);int sent=sendto(socket.value,"x",1,0,reinterpret_cast<sockaddr*>(&target),sizeof(target));
    return sent==1?0:WSAGetLastError();
}
static int connectTCP(const std::string& ip,unsigned short port){
    Socket socket;socket.value=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);require(socket.value!=INVALID_SOCKET,"TCP socket failed");
    auto target=endpoint(ip,port);int result=connect(socket.value,reinterpret_cast<sockaddr*>(&target),sizeof(target));return result==0?0:WSAGetLastError();
}
static void bindSocket(Socket& socket,int kind,const std::string& ip,unsigned short port){
    socket.value=::socket(AF_INET,kind,kind==SOCK_DGRAM?IPPROTO_UDP:IPPROTO_TCP);require(socket.value!=INVALID_SOCKET,"Fixture socket failed");
    BOOL exclusive=TRUE;setsockopt(socket.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive));
    auto address=endpoint(ip,port);require(bind(socket.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"Fixture port is already owned");
    if(kind==SOCK_STREAM)require(listen(socket.value,8)==0,"Fixture listen failed");
}
int wmain(int argc,wchar_t** argv){
    WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))return 1;
    try{
        if(argc==3){std::wstring host=argv[1];std::string ip(host.begin(),host.end());return sendUDP(ip,static_cast<unsigned short>(std::stoul(argv[2])))==0?0:1;}
        require(GetEnvironmentVariableW(L"GITHUB_ACTIONS",nullptr,0)!=0,"Disposable hosted runner required");
        auto ip=localIP();Socket quic,dnsUDP,dnsTCP;
        bindSocket(quic,SOCK_DGRAM,ip,443);bindSocket(dnsUDP,SOCK_DGRAM,ip,53);bindSocket(dnsTCP,SOCK_STREAM,ip,53);
        require(sendUDP(ip,443)==0&&sendUDP(ip,53)==0&&connectTCP(ip,53)==0,"Unfiltered local fixture not reachable");
        wchar_t exe[32768]{};require(GetModuleFileNameW(nullptr,exe,32768)!=0,"Executable identity unavailable");
        SafetyFilters filters;filters.start({exe},true);
        int quicError=sendUDP(ip,443),udpError=sendUDP(ip,53),tcpError=connectTCP(ip,53);
        std::cout<<"WFP errors: QUIC="<<quicError<<" UDP53="<<udpError<<" TCP53="<<tcpError<<"\n";
        require(quicError==WSAEACCES&&udpError==WSAEACCES&&tcpError==WSAEACCES,"WFP did not deny selected QUIC and direct DNS");
        // Loopback stub traffic is not blocked by the remote-DNS guard.
        Socket loop;bindSocket(loop,SOCK_DGRAM,"127.0.0.1",53);require(sendUDP("127.0.0.1",53)==0,"Loopback DNS stub was blocked");
        auto other=std::filesystem::path(exe).parent_path()/L"unselected-network-fixture.exe";
        require(!std::filesystem::exists(other),"Unselected fixture already exists");std::filesystem::copy_file(exe,other);
        struct Cleanup{std::filesystem::path path;~Cleanup(){std::error_code error;std::filesystem::remove(path,error);}} cleanup{other};
        auto command=native_ipc::quote(other.wstring())+L" "+native_ipc::wide(ip)+L" 443";
        STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
        require(CreateProcessW(other.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)!=0,"Cannot start unselected fixture");
        auto waited=WaitForSingleObject(pi.hProcess,5000);DWORD code=1;
        if(waited!=WAIT_OBJECT_0){TerminateProcess(pi.hProcess,1);WaitForSingleObject(pi.hProcess,3000);}else GetExitCodeProcess(pi.hProcess,&code);
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);require(code==0,"Unselected application QUIC was blocked");
        filters.stop();require(sendUDP(ip,443)==0&&sendUDP(ip,53)==0&&connectTCP(ip,53)==0,"Dynamic safety filters survived Stop");
        std::cout<<"PASS: real WFP selected-EXE UDP443 blocking, global non-loopback UDP/TCP53 blocking, local DNS exemption, unselected-app bypass and rollback. IPv6 filters installed; IPv6 traffic not exercised.\n";
        WSACleanup();return 0;
    }catch(const std::exception& error){std::cerr<<"FAIL: "<<error.what()<<"\n";WSACleanup();return 1;}
}
