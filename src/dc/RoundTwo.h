#ifndef THREEPP_ROUNDTWO_H
#define THREEPP_ROUNDTWO_H

#include <array>
#include <vector>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/drbg.h>
#include <cryptopp/modes.h>
#include <unordered_map>
#include "DCState.h"
#include "../datastruct/ReceivedMessage.h"

class RoundTwo : public DCState {
public:
    RoundTwo(DCNetwork& DCNet, int slotIndex, std::vector<uint16_t>& slots);

    RoundTwo(DCNetwork& DCNet, int slotIndex, std::vector<uint16_t>& slots, std::vector<std::vector<std::array<uint8_t, 32>>>& seeds);

    virtual ~RoundTwo();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void sharingPartOne(size_t totalNumSlices, std::vector<std::vector<std::vector<CryptoPP::Integer>>>& shares);

    int sharingPartTwo(size_t totalNumSlices);

    std::vector<std::vector<uint8_t>> resultComputation();

    inline CryptoPP::ECPPoint commit(CryptoPP::Integer &r, CryptoPP::Integer &s);

    void injectBlameMessage(uint32_t suspectID, uint32_t slot, uint32_t slice, CryptoPP::Integer& s);

    void handleBlameMessage(std::shared_ptr<ReceivedMessage>& blameMessage);

    DCNetwork& DCNetwork_;

    // determines if the commitment mechanism is used
    bool securedRound_;

    // DCNetwork size
    size_t k_;

    // the position in of the own nodeID in the ordered member list
    size_t nodeIndex_;

    // index of the slot in the message vector
    int slotIndex_;

    std::vector<uint16_t> slots_;

    std::vector<std::vector<std::array<uint8_t, 32>>> seeds_;

    // pseudo random values for the commitments
    std::vector<std::vector<std::vector<std::vector<CryptoPP::Integer>>>> rValues_;

    // received commitments stored along with the corresponding memberID
    std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments_;

    // sum of all shares
    std::vector<std::vector<CryptoPP::Integer>> S;

    // sum of all random blinding coefficients
    std::vector<std::vector<CryptoPP::Integer>> R;

    // sum of all commitments
    std::vector<std::vector<CryptoPP::ECPPoint>> C;

    CryptoPP::AutoSeededRandomPool PRNG;

    // Deterministic random number generator
    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption DRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
};


#endif //THREEPP_ROUNDTWO_H
