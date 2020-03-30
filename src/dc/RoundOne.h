#ifndef THREEPP_ROUNDONE_H
#define THREEPP_ROUNDONE_H

#include <cryptopp/ecpoint.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>

#include <unordered_map>
#include "DCState.h"
#include "../datastruct/ReceivedMessage.h"

extern std::mutex mutex_;

class RoundOne : public DCState {
public:
    RoundOne(DCNetwork& DCNet, bool securedRound);

    virtual ~RoundOne();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void sharingPartOne(std::vector<std::vector<CryptoPP::Integer>>& shares);

    void sharingPartTwo();

    std::vector<uint8_t> resultComputation();

    void printMessageVector(std::vector<uint8_t>& msgVector);

    DCNetwork& DCNetwork_;

    // determines if the commitment mechanism is used
    bool securedRound_;

    // DCNetwork size
    size_t k_;

    // the position in of the own nodeID in the ordered member list
    size_t nodeIndex_;

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
