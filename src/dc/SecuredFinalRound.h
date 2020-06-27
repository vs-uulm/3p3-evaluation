#ifndef THREEPP_SECUREDFINALROUND_H
#define THREEPP_SECUREDFINALROUND_H

#include <array>
#include <vector>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/drbg.h>
#include <cryptopp/modes.h>
#include <unordered_map>
#include <cryptopp/crc.h>
#include "DCState.h"
#include "../datastruct/ReceivedMessage.h"

class SecuredFinalRound : public DCState {
public:
    SecuredFinalRound(DCNetwork& DCNet, int slotIndex, std::vector<uint16_t> slots,
            std::vector<CryptoPP::Integer> seedPrivateKeys, std::vector<std::array<uint8_t, 32>> receivedSeeds);

    virtual ~SecuredFinalRound();

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

    // index of the slot in the message vector
    int slotIndex_;

    std::vector<uint16_t> slots_;

    std::vector<CryptoPP::Integer> seedPrivateKeys_;

    std::vector<std::array<uint8_t, 32>> seeds_;

    // pseudo random values for the commitments
    std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues_;

    // received commitments stored along with the corresponding memberID
    std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments_;

    // share and rvalue storage, required for delayed commitment validation
    std::unordered_map<uint32_t, std::vector<std::vector<std::pair<CryptoPP::Integer, CryptoPP::Integer>>>> rs_;
    std::unordered_map<uint32_t, std::vector<std::vector<std::pair<CryptoPP::Integer, CryptoPP::Integer>>>> RS_;

    // sum of all shares
    std::vector<std::vector<CryptoPP::Integer>> S;

    // sum of all random blinding coefficients
    std::vector<std::vector<CryptoPP::Integer>> R;

    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::CRC32 CRC32_;

    // Deterministic random number generator
    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption DRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;

    bool delayedVerification_;
};


#endif //THREEPP_SECUREDFINALROUND_H
