#ifndef THREEPP_SEEDROUND_H
#define THREEPP_SEEDROUND_H

#include <cryptopp/ecpoint.h>
#include <cryptopp/crc.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>

#include <unordered_map>
#include "DCState.h"
#include "../datastruct/ReceivedMessage.h"

class SeedRound : public DCState {
public:
    SeedRound(DCNetwork& DCNet, int slotIndex, std::vector<uint16_t> slots);

    virtual ~SeedRound();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void sharingPartOne(std::vector<std::vector<std::vector<CryptoPP::Integer>>>& shares);

    int sharingPartTwo();

    std::vector<std::vector<uint8_t>> resultComputation();

    void injectBlameMessage(uint32_t suspectID, uint32_t slice, CryptoPP::Integer& r, CryptoPP::Integer& s);

    void handleBlameMessage(std::shared_ptr<ReceivedMessage>& blameMessage);

    void printMessageVector(std::vector<uint8_t>& msgVector);

    inline CryptoPP::ECPPoint commit(CryptoPP::Integer& r, CryptoPP::Integer& s);

    DCNetwork& DCNetwork_;

    // DCNetwork size
    size_t k_;

    // the position in of the own nodeID in the ordered member list
    size_t nodeIndex_;

    int slotIndex_;

    std::vector<uint16_t> slots_;

    std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments_;

    std::vector<std::vector<CryptoPP::Integer>> S;

    std::vector<std::vector<CryptoPP::Integer>> R;

    std::vector<std::vector<CryptoPP::ECPPoint>> C;

    std::vector<std::array<uint8_t, 32>> submittedSeeds_;

    CryptoPP::CRC32 CRC32_;

    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;
};


#endif //THREEPP_SEEDROUND_H
