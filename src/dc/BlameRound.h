#ifndef THREEPP_BLAMEROUND_H
#define THREEPP_BLAMEROUND_H

#include <cryptopp/crc.h>
#include <cryptopp/modes.h>
#include "DCNetwork.h"
#include "DCState.h"

class BlameRound : public DCState {
public:
    BlameRound(DCNetwork& DCNet, std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> oldCommitments);

    BlameRound(DCNetwork& DCNet, int slot, uint16_t slice, uint32_t suspiciousMember_, CryptoPP::Integer seedPrivateKey,
               std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> oldCommitments);

    virtual ~BlameRound();

    virtual std::unique_ptr<DCState> executeTask();

private:
    void sharingPartOne(std::vector<std::vector<std::vector<CryptoPP::Integer>>>& shares);

    int sharingPartTwo();

    std::vector<std::vector<uint8_t>> resultComputation();

    void injectBlameMessage(uint32_t suspectID, uint32_t slot, uint32_t slice, CryptoPP::Integer& r, CryptoPP::Integer& s);

    void handleBlameMessage(ReceivedMessage& blameMessage);

    inline CryptoPP::ECPPoint commit(CryptoPP::Integer& r, CryptoPP::Integer& s);

    DCNetwork& DCNetwork_;

    // DCNetwork size
    size_t k_;

    // the position in of the own nodeID in the ordered member list
    size_t nodeIndex_;

    int slotIndex_;

    uint16_t sliceIndex_;

    uint32_t suspiciousMember_;

    CryptoPP::Integer seedPrivateKey_;

    std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> oldCommitments_;

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues_;

    std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments_;

    // sum of all shares
    std::vector<std::vector<CryptoPP::Integer>> S;

    // sum of all random blinding coefficients
    std::vector<std::vector<CryptoPP::Integer>> R;

    // sum of all commitments
    std::vector<std::vector<CryptoPP::ECPPoint>> C;

    CryptoPP::CRC32 CRC32_;

    CryptoPP::AutoSeededRandomPool PRNG;

    // Deterministic random number generator
    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption DRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;
};


#endif //THREEPP_BLAMEROUND_H
