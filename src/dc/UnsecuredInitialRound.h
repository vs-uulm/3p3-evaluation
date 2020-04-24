#ifndef THREEPP_UNSECUREDINITIALROUND_H
#define THREEPP_UNSECUREDINITIALROUND_H

#include <cryptopp/osrng.h>
#include <cryptopp/crc.h>
#include "DCState.h"

class UnsecuredInitialRound : public DCState {
public:
    UnsecuredInitialRound(DCNetwork& DCNet);

    virtual ~UnsecuredInitialRound();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void sharingPartOne(std::vector<std::vector<uint8_t>>& shares);

    void sharingPartTwo();

    void resultComputation();

    void printSlots(std::vector<uint8_t>& slots);

    DCNetwork& DCNetwork_;

    // DCNetwork size
    size_t k_;

    // the position in of the own nodeID in the ordered member list
    size_t nodeIndex_;

    // sum of all shares
    std::vector<uint8_t> S;

    CryptoPP::CRC32 CRC32_;

    CryptoPP::AutoSeededRandomPool PRNG;
};


#endif //THREEPP_UNSECUREDINITIALROUND_H
