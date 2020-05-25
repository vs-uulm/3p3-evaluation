#ifndef THREEPP_UNSECUREDFINALROUND_H
#define THREEPP_UNSECUREDFINALROUND_H

#include <cryptopp/osrng.h>
#include <cryptopp/crc.h>
#include "DCState.h"

class UnsecuredFinalRound : public DCState {
public:
    UnsecuredFinalRound(DCNetwork& DCNet, int slotIndex, std::vector<uint16_t> slots);

    virtual ~UnsecuredFinalRound();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void sharingPartOne(std::vector<std::vector<std::vector<uint8_t>>>& shares);

    void sharingPartTwo();

    void resultComputation();

    DCNetwork& DCNetwork_;

    // DCNetwork size
    size_t k_;

    // the position in of the own nodeID in the ordered member list
    size_t nodeIndex_;

    // index of the slot in the message vector
    int slotIndex_;

    std::vector<uint16_t> slots_;

    // sum of all shares
    std::vector<std::vector<uint8_t>> S;

    CryptoPP::CRC32 CRC32_;

    CryptoPP::AutoSeededRandomPool PRNG;
};


#endif //THREEPP_UNSECUREDFINALROUND_H
