#include "Utils.h"

#include <array>
#include <openssl/ec.h>
#include <cryptopp/sha.h>


std::string utils::sha256(std::vector<uint8_t>& data) {
    CryptoPP::SHA256 sha256;

    std::string hash;
    hash.resize(32);
    sha256.Update(reinterpret_cast<CryptoPP::byte*>(data.data()), data.size());
    sha256.Final(reinterpret_cast<CryptoPP::byte*>(hash.data()));
    return hash;
}
