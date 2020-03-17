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


    std::vector<std::vector<uint8_t>> shares;
    shares.resize(k);

    // fill k-1 shares with random data
    for(auto it = shares.begin(); it < shares.end()-1; it++) {
        it->reserve(sizeMsg1);
        PRNG.GenerateBlock(it->data(), sizeMsg1);
    }

    // calculate the k-th share
    shares[k-1] = msgVec;
    for(int i=0; i<sizeMsg1; i++)
        for(int j=0; j<k-1; j++)
            shares[k-1][i] ^= shares[j][i];

    // generate and broadcast the commitments for the first round
    commitRoundOne(shares, sizeMsg1);

    return std::make_unique<Init>(DCNetwork_);
}


void RoundOne::commitRoundOne(std::vector<std::vector<uint8_t>> &shares, size_t sizeMsg1) {
    size_t k = DCNetwork_.members().size() + 1;

    // Create the commitments
    typedef std::array<CryptoPP::byte, 32> Slot;

    size_t commitSlots = std::ceil(sizeMsg1 / 31);

    std::vector<std::vector<Slot>> commitments;
    commitments.resize(k);
    for(auto& share : commitments)
        share.reserve(commitSlots);

    std::vector<std::vector<Slot>> randomness;
    randomness.resize(k);
    for(auto& share : randomness)
        share.reserve(commitSlots);
    double elapsed = 0;
    for(int i=0; i < k; i++) {
        for (int j = 0; j < commitSlots; j++) {
            // generate random blinding coefficient
            Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());

            // store in the raw bytes of the blinding coefficient
            r.Encode(randomness[i][j].data(), 32);

            // a 31 Byte slot of the i-th share
            Integer s(&shares[i][31*j], 31);
            auto start = std::chrono::high_resolution_clock::now();
            ECPPoint first = curve.GetCurve().ScalarMultiply(G, r);
            ECPPoint second = curve.GetCurve().ScalarMultiply(H, s);
            ECPPoint C = curve.GetCurve().Add(first, second);
            auto finish = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> duration = finish - start;
            elapsed += duration.count();
            curve.EncodeElement(false, C, commitments[i][j].data());
        }
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Finished in: " << elapsed << std::endl;
    }
}