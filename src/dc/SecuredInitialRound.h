#ifndef THREEPP_SECUREDINITIALROUND_H
#define THREEPP_SECUREDINITIALROUND_H

#include <cryptopp/ecpoint.h>
#include <cryptopp/crc.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>

#include <unordered_map>
#include "DCState.h"
#include "../datastruct/ReceivedMessage.h"

extern std::mutex mutex_;

class SecuredInitialRound : public DCState {
public:
    SecuredInitialRound(DCNetwork& DCNet);

    virtual ~SecuredInitialRound();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void sharingPartOne(std::vector<std::vector<std::vector<CryptoPP::Integer>>>& shares);

    int sharingPartTwo();

    std::vector<std::vector<uint8_t>> resultComputation();

    void injectBlameMessage(uint32_t suspectID, uint32_t slot, uint32_t slice, CryptoPP::Integer& r, CryptoPP::Integer& s);

    void handleBlameMessage(ReceivedMessage& blameMessage);

    DCNetwork& DCNetwork_;

    // DCNetwork size
    size_t k_;

    // the position in of the own nodeID in the ordered member list
    size_t nodeIndex_;

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues_;

    // initial commitments stored with the corresponding senderID
    std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments_;

    // sum of all shares
    std::vector<std::vector<CryptoPP::Integer>> S;

    // sum of all random blinding coefficients
    std::vector<std::vector<CryptoPP::Integer>> R;

    CryptoPP::CRC32 CRC32_;

    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;
};


#endif //THREEPP_SECUREDINITIALROUND_H
