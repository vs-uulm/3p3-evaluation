#ifndef THREEPP_ROUNDONE_H
#define THREEPP_ROUNDONE_H

#include <cryptopp/ecpoint.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include "DCState.h"
#include "../datastruct/ReceivedMessage.h"

class RoundOne : public DCState {
public:
    RoundOne(DCNetwork& DCNet);

    virtual ~RoundOne();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void commitRoundOne(std::vector<std::vector<CryptoPP::Integer>>& shares, std::vector<uint8_t>& messageVec);

    void validateCommitments(std::vector<uint8_t>& messageVec, std::vector<std::vector<CryptoPP::Integer>>& shares,
        std::vector<std::vector<CryptoPP::Integer>>& randomness,
        std::vector<std::vector<std::array<uint8_t, 33>>>& commitments);

    DCNetwork& DCNetwork_;

    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
};


#endif //THREEPP_ROUNDONE_H
