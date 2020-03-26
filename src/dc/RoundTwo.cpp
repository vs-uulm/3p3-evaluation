#include <iostream>
#include "RoundTwo.h"
#include "Init.h"

RoundTwo::RoundTwo(DCNetwork &DCNet, bool securedRound, size_t p, std::vector<std::array<uint8_t, 32>>& K, std::vector<uint16_t>& L)
: DCNetwork_(DCNet), k_(DCNetwork_.members().size()), securedRound_(securedRound), p_(p), K(std::move(K)), L(std::move(L)) {}


RoundTwo::~RoundTwo() {}

std::unique_ptr<DCState> RoundTwo::executeTask() {
    std::vector<uint8_t> submittedMessage;

    uint16_t l = 0;
    if(p_ > -1) {
        submittedMessage = DCNetwork_.submittedMessages().front();
        DCNetwork_.submittedMessages().pop();

        // ensure that the message size does not exceed 2^16 Bytes
        l = submittedMessage.size() > USHRT_MAX ? USHRT_MAX : submittedMessage.size();
    }

    std::vector<std::vector<uint8_t>> msgSlots;
    // Split the message vector into slices of 31 Bytes
    size_t numSlices = std::ceil(msgVector_.size() / 31.0);
    std::vector<CryptoPP::Integer> msgSlices;
    msgSlices.reserve(numSlices);

    for(int i=0; i<numSlices; i++) {
        size_t sliceSize = ((msgVector_.size() - 31 * i > 31) ? 31 : msgVector_.size() - 31 * i);
        CryptoPP::Integer slice(&msgVector_[31 * i], sliceSize);
        msgSlices.push_back(std::move(slice));
    }


    // Split each slice into k shares
    std::vector<std::vector<CryptoPP::Integer>> shares;
    shares.resize(k_);

    // initialize the slices of the k-th share with zeroes
    shares[k_-1].resize(numSlices);
    // fill the first k-1 set of shares with random data
    for(int i=0; i<k_-1; i++) {
        shares[i].reserve(numSlices);
        for(int j=0; j<numSlices; j++) {
            CryptoPP::Integer slice(PRNG, Integer::One(), curve.GetMaxExponent());
            shares[k_-1][j] -= slice;
            shares[i].push_back(std::move(slice));
        }
    }

    // calculate the k-th share
    for(int j = 0; j < numSlices; j++) {
        shares[k_-1][j] += msgSlices[j];
        shares[k_-1][j] = shares[k_-1][j].Modulo(curve.GetSubgroupOrder());
    }

    // store the slices of the own share in S
    S.resize(numSlices);

    // get the index of the own share by checking the position of the local nodeID in the member list
    int index = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
    for(int j=0; j<numSlices; j++) {
        S[j] = shares[index][j];
    }

    return std::make_unique<Init>(DCNetwork_);
}