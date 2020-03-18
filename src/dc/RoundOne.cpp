#include <iostream>
#include <thread>
#include <cryptopp/oids.h>
#include <iomanip>
#include "RoundOne.h"
#include "Init.h"

std::mutex mutex_;

RoundOne::RoundOne(DCNetwork& DCNet) : DCNetwork_(DCNet) {
    curve.Initialize(CryptoPP::ASN1::secp256k1());
}

RoundOne::~RoundOne() {

}

std::unique_ptr<DCState> RoundOne::executeTask() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Entering round one" << std::endl;
    }

    std::shared_ptr<std::vector<uint8_t>> message;
    // determine the size of the broadcast message
    // if there is no message to be sent, the size remains zero
    uint16_t l = 0;
    if (!DCNetwork_.submittedMessages().empty()) {
        message = DCNetwork_.submittedMessages().pop();
        l = message->size() > USHRT_MAX ? USHRT_MAX : message->size();
    }

    size_t k = DCNetwork_.members().size() + 1;
    k = 6;
    // calculate the size of the message vector
    size_t sizeMsg1 = 2*k * (4 + 32*k);
    // Initialize the message vector with zeroes
    std::vector<uint8_t> msgVec(sizeMsg1,0);

    // TODO for tests only
    l = 32;

    if (l > 0) {
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        uint16_t p = PRNG.GenerateWord32(0, 2*k - 1);

        // set the values in Big Endian format
        msgVec[4*p] = static_cast<uint8_t>((r & 0xFF00) >> 8);
        msgVec[4*p + 1] = static_cast<uint8_t>((r & 0x00FF));
        msgVec[4*p + 2] = static_cast<uint8_t>((l & 0xFF00) >> 8);
        msgVec[4*p + 3] = static_cast<uint8_t>((l & 0x00FF));

        // generate k random K values used as seeds
        // for the commitments of the second round
        PRNG.GenerateBlock(&msgVec[8*k + p * 32*k], 32*k);
    }

    size_t numSlots = std::ceil(sizeMsg1 / 31);
    std::vector<std::vector<CryptoPP::Integer>> shares;
    shares.resize(k);

    // init the k-th set of shares with zeroes
    shares[k-1].resize(numSlots);

    // fill the first k-1 set of shares with random data
    for(int i=0; i<k-1; i++) {
        shares[i].reserve(numSlots);
        for(int j=0; j<numSlots; j++) {
            CryptoPP::Integer slot(PRNG, Integer::One(), curve.GetMaxExponent());
            shares[i].push_back(slot);
            shares[k-1][j] -= slot;
        }
        //std::cout << shares[i].size() << std::endl;
    }

    // calculate the k-th share
    for (int j = 0; j < numSlots; j++) {
        size_t sliceSize = ((sizeMsg1 - 31 * (j + 1) >= 31) ? 31 : sizeMsg1 - 31 * (j + 1));
        CryptoPP::Integer slice(&msgVec[31 * j], sliceSize);
        shares[k-1][j] += slice;
        shares[k-1][j].Modulo(curve.GetSubgroupOrder());
    }
    // generate and broadcast the commitments for the first round
    commitRoundOne(shares);

    return std::make_unique<Init>(DCNetwork_);
}


void RoundOne::commitRoundOne(std::vector<std::vector<CryptoPP::Integer>>& shares) {
    size_t k = DCNetwork_.members().size() + 1;

    size_t commitSlots = shares[0].size();
    std::vector<std::vector<std::array<uint8_t, 33>>> commitments;
    commitments.resize(k);
    for(auto& share : commitments)
        share.reserve(commitSlots);

    //std::vector<std::vector<std::array<CryptoPP::byte, 32>>> randomness;
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<CryptoPP::Integer>> randomness;
    randomness.resize(k);
    for(auto& share : randomness)
        share.resize(commitSlots);

    // measure the time it takes to generate all commitments
    for(int i=0; i < k; i++) {
        for (int j=0; j < commitSlots; j++) {
            // generate the randomness r for this slice of the share
            randomness[i][j] = (PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());

            ECPPoint rG = curve.GetCurve().ScalarMultiply(G, randomness[i][j]);
            ECPPoint xH = curve.GetCurve().ScalarMultiply(H, shares[i][j]);
            ECPPoint C = curve.GetCurve().Add(rG, xH);

            curve.GetCurve().EncodePoint(commitments[i][j].data(), C, true);
            for(uint8_t c : commitments[i][j])
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
            std::cout << std::endl;
        }
    }
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = finish - start;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Finished in: " << duration.count() << std::endl;
    }
}

void RoundOne::validateCommitments(std::vector<uint8_t> messageVec,
        std::vector<std::vector<CryptoPP::Integer>>& shares,
        std::vector<std::vector<CryptoPP::Integer>> randomness,
        std::vector<std::vector<std::array<uint8_t, 33>>> commitments) {

}