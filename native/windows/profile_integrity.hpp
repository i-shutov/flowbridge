#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>

// A one-shot SHA-256 pins the GUI-validated native JSON bytes across the UAC
// delay. This is an integrity/TOCTOU check, not a secret or an authentication
// token. The elevated helper still validates the profile and owner separately.
namespace profile_integrity {
inline std::string sha256(const std::string& bytes) {
    if(bytes.empty()||bytes.size()>1024*1024)
        throw std::runtime_error("Native capture profile must contain 1..1048576 bytes");
    BCRYPT_ALG_HANDLE algorithm=nullptr;
    if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)
        throw std::runtime_error("Cannot initialize Windows SHA-256 provider");
    struct CloseAlgorithm {
        BCRYPT_ALG_HANDLE value;
        ~CloseAlgorithm(){if(value)BCryptCloseAlgorithmProvider(value,0);}
    } close{algorithm};
    std::array<unsigned char,32> digest{};
    auto input=reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data()));
    if(BCryptHash(algorithm,nullptr,0,input,static_cast<ULONG>(bytes.size()),
                  digest.data(),static_cast<ULONG>(digest.size()))<0)
        throw std::runtime_error("Cannot SHA-256 hash native capture profile");
    constexpr char Hex[]="0123456789abcdef";
    std::string result;
    result.reserve(64);
    for(unsigned char byte:digest) {
        result.push_back(Hex[byte>>4]);
        result.push_back(Hex[byte&15]);
    }
    return result;
}
inline bool valid(const std::string& expected) {
    return expected.size()==64 && std::all_of(expected.begin(),expected.end(),
           [](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});
}
inline bool identical(const std::string& a,const std::string& b) {
    if(!valid(a)||!valid(b)) return false;
    // Fixed-time comparison is cheap even though this digest is not a secret.
    unsigned char difference=0;
    for(std::size_t i=0;i<64;++i)
        difference|=static_cast<unsigned char>(a[i]^b[i]);
    return difference==0;
}
} // namespace profile_integrity
