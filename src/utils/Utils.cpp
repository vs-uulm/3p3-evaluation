#include "Utils.h"

#include <openssl/ec.h>
#include <cryptopp/sha.h>


std::vector<uint8_t> utils::sha256(std::vector<uint8_t>& data) {
    CryptoPP::SHA256 sha256;

    std::vector<uint8_t> hash;
    sha256.Update(reinterpret_cast<CryptoPP::byte*>(data.data()), data.size());
    hash.resize(sha256.DigestSize());
    sha256.Final(reinterpret_cast<CryptoPP::byte*>(hash.data()));
    return hash;
}
