#ifndef THREEPP_ROUNDONE_H
#define THREEPP_ROUNDONE_H

#include <cryptopp/ecpoint.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include "DCState.h"

class RoundOne : public DCState {
public:
    RoundOne(DCNetwork& DCNet);

    virtual ~RoundOne();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void commitRoundOne(std::vector<std::vector<uint8_t>>& shares, size_t sizeMsg1);

    DCNetwork& DCNetwork_;

    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
};


#endif //THREEPP_ROUNDONE_H
