#ifndef THREEPP_UTILS_H
#define THREEPP_UTILS_H

#include <vector>
#include <openssl/evp.h>
#include <cryptopp/ecpoint.h>
#include <cryptopp/randpool.h>

namespace utils {
    std::string sha256(std::vector<uint8_t>& data);
};


#endif //THREEPP_UTILS_H
