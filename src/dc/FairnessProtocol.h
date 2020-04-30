#ifndef THREEPP_FAIRNESSPROTOCOL_H
#define THREEPP_FAIRNESSPROTOCOL_H


#include <cryptopp/integer.h>
#include <cryptopp/ecpoint.h>
#include <unordered_map>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include "DCState.h"

enum Outcome {
    OpenCommitments,
    ProofOfKnowledge
};

class FairnessProtocol : public DCState {
public:
    FairnessProtocol(DCNetwork& DCNet, size_t slotIndex, std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues,
            std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments);

    virtual ~FairnessProtocol();

    virtual std::unique_ptr<DCState> executeTask();

private:
    CryptoPP::ECPPoint commit(CryptoPP::Integer &r, CryptoPP::Integer &s);

    int coinFlip();

    void distributeCommitments();

    int openCommitments();

    int proofKnowledge();

    DCNetwork& DCNetwork_;

    // DCNetwork size
    size_t k_;

    size_t slotIndex_;

    // the position in of the own nodeID in the ordered member list
    size_t nodeIndex_;

    //std::unordered_map<uint32_t, std::vector<bool>> validatedSlots_;

    Outcome outcome_;

    std::vector<std::vector<CryptoPP::Integer>> r_;

    std::vector<std::vector<CryptoPP::Integer>> rho_;

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues_;

    // initial commitments stored with the corresponding senderID
    std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments_;

    std::unordered_map<uint32_t, std::vector<std::vector<CryptoPP::ECPPoint>>> newCommitments_;

    std::vector<uint32_t> permutation_;

    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;
};


#endif //THREEPP_FAIRNESSPROTOCOL_H
