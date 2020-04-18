#ifndef THREEPP_ROUNDONEUNSECURED_H
#define THREEPP_ROUNDONEUNSECURED_H


#include <cryptopp/integer.h>
#include <cryptopp/ecpoint.h>
#include <cryptopp/ecp.h>
#include <cryptopp/osrng.h>
#include <cryptopp/crc.h>
#include <cryptopp/eccrypto.h>
#include "DCState.h"
#include "../datastruct/ReceivedMessage.h"

class RoundOneUnsecured : public DCState {
public:
    RoundOneUnsecured(DCNetwork& DCNet);

    virtual ~RoundOneUnsecured();

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

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;

};


#endif //THREEPP_ROUNDONEUNSECURED_H
