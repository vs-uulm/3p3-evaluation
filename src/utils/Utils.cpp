#include "Utils.h"

#include <iostream>
#include <openssl/ec.h>
#include <cryptopp/sha.h>

void utils::seed_PRNG() {
    FILE* fp = fopen("/dev/urandom", "r");
    uint8_t randomData[32];
    ssize_t num_bytes = fread(randomData, 1, 32, fp);
    if(num_bytes < 32) {
        std::cout << "Error: could not read enough random data" << std::endl;
    }
}

EVP_PKEY* utils::generate_ec_key_pair() {
    seed_PRNG();
    EVP_PKEY* evp_pkey = EVP_PKEY_new();
    EC_KEY* ec_key_pair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(EC_KEY_generate_key(ec_key_pair) == 0) {
        return nullptr;
    }
    if(EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key_pair) < 1) {
        return nullptr;
    }
    return evp_pkey;
}

EVP_PKEY* utils::process_raw_public_key(std::vector<uint8_t>& raw_ec_pkey) {
    EVP_PKEY* evp_pkey = EVP_PKEY_new();
    BIGNUM* g_x = BN_new();
    BIGNUM* g_y = BN_new();

    BN_bin2bn(raw_ec_pkey.data(), 32, g_x);
    BN_bin2bn(raw_ec_pkey.data() + 32, 32, g_y);

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    int result = EC_KEY_set_public_key_affine_coordinates(ec_key, g_x, g_y);

    BN_free(g_x);
    BN_free(g_y);

    if(result < 1) {
        EVP_PKEY_free(evp_pkey);
        EC_KEY_free(ec_key);
        return nullptr;
    }

    EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key);
    return evp_pkey;
}

std::vector<uint8_t> utils::sha256(std::vector<uint8_t>& data) {
    CryptoPP::SHA256 sha256;

    std::vector<uint8_t> hash;
    sha256.Update(reinterpret_cast<CryptoPP::byte*>(data.data()), data.size());
    hash.resize(sha256.DigestSize());
    sha256.Final(reinterpret_cast<CryptoPP::byte*>(hash.data()));
    return hash;
}