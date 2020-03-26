#ifndef THREEPP_ROUNDONE_H
#define THREEPP_ROUNDONE_H

#include <cryptopp/ecpoint.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include "DCState.h"
#include "../datastruct/ReceivedMessage.h"

class RoundOne : public DCState {
public:
    RoundOne(DCNetwork& DCNet, bool securedRound);

    virtual ~RoundOne();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void sharingPartOne(std::vector<std::vector<CryptoPP::Integer>>& shares, size_t numSlices);

    void sharingPartTwo(size_t numSlices);

    std::vector<uint8_t> resultComputation(size_t numSlices);

    void printMessageVector(std::vector<uint8_t>& msgVector);

    DCNetwork& DCNetwork_;

    // determines if the commitment mechanism is used
    bool securedRound_;

    // DCNetwork size
    size_t k_;

    std::vector<uint8_t> msgVector_;

    // initial commitments stored with the corresponding senderID
    std::unordered_map<uint32_t, std::vector<std::vector<CryptoPP::ECPPoint>>> commitments_;

    // sum of all shares
    std::vector<CryptoPP::Integer> S;

    // sum of all random blinding coefficients
    std::vector<CryptoPP::Integer> R;

    // sum of all commitments
    std::vector<CryptoPP::ECPPoint> C;

    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
};


#endif //THREEPP_ROUNDONE_H
