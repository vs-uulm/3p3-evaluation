#ifndef THREEPP_ROUNDTWO_H
#define THREEPP_ROUNDTWO_H

#include <array>
#include <vector>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include "DCState.h"

class RoundTwo : public DCState {
public:
    RoundTwo(DCNetwork& DCNet, bool securedRound, size_t p, std::vector<std::array<uint8_t, 32>>& K, std::vector<uint16_t>& L);

    virtual ~RoundTwo();

    virtual std::unique_ptr<DCState> executeTask();

private:
    DCNetwork& DCNetwork_;

    // determines if the commitment mechanism is used
    bool securedRound_;

    // DCNetwork size
    size_t k_;

    std::vector<uint8_t> msgVector_;

    size_t p_;

    std::vector<std::array<uint8_t, 32>> K;

    std::vector<uint16_t> L;

    // sum of all shares
    std::vector<CryptoPP::Integer> S;

    // sum of all random blinding coefficients
    std::vector<CryptoPP::Integer> R;

    // sum of all commitments
    std::vector<CryptoPP::ECPPoint> C;

    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
};


#endif //THREEPP_ROUNDTWO_H
