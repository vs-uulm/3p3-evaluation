#ifndef THREEPP_UTILS_H
#define THREEPP_UTILS_H

#include <vector>
#include <openssl/evp.h>

namespace utils {
    void seed_PRNG();
    EVP_PKEY* generate_ec_key_pair();
    EVP_PKEY* process_raw_public_key(std::vector<uint8_t>& raw_ec_pkey);
};


#endif //THREEPP_UTILS_H