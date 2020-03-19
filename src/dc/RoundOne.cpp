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
    // TODO undo
    size_t k = DCNetwork_.members().size() + 1;
    k = 16;
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
    std::cout << "Size message vector: " << sizeMsg1 << std::endl;
    size_t numSlots = std::ceil(sizeMsg1 / 31.0);
    std::cout << "Num slots: " << numSlots << std::endl;
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
    }

    // calculate the k-th share
    for (int j = 0; j < numSlots; j++) {
        size_t sliceSize = ((sizeMsg1 - 31 * (j) > 31) ? 31 : sizeMsg1 - 31 * (j));
        CryptoPP::Integer slice(&msgVec[31 * j], sliceSize);
        shares[k-1][j] += slice;
        shares[k-1][j] = shares[k-1][j].Modulo(curve.GetSubgroupOrder());
    }
    // generate and broadcast the commitments for the first round
    commitRoundOne(shares, msgVec);

    return std::make_unique<Init>(DCNetwork_);
}


void RoundOne::commitRoundOne(std::vector<std::vector<CryptoPP::Integer>>& shares, std::vector<uint8_t>& messageVec) {
    size_t k = shares.size();

    size_t commitSlots = shares[0].size();
    std::vector<std::vector<std::array<uint8_t, 33>>> commitments;
    commitments.resize(k);
    for(auto& share : commitments)
        share.resize(commitSlots);

    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<CryptoPP::Integer>> randomness;
    randomness.resize(k);
    for(auto& share : randomness)
        share.reserve(commitSlots);

    // measure the time it takes to generate all the commitments
    for(int i=0; i < k; i++) {
        for (int j=0; j < commitSlots; j++) {
            // generate the randomness r for this slice of the share
            CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
            //randomness[i][j] = std::move(r);
            randomness[i].push_back(std::move(r));
            CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, randomness[i][j]);
            CryptoPP::ECPPoint xH = curve.GetCurve().ScalarMultiply(H, shares[i][j]);
            CryptoPP::ECPPoint C = curve.GetCurve().Add(rG, xH);

            // compress the commitment to 33 bytes
            curve.GetCurve().EncodePoint(commitments[i][j].data(), C, true);
        }
    }

    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = finish - start;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Finished in: " << duration.count() << std::endl;
    }

    validateCommitments(messageVec, shares, randomness, commitments);
}

void RoundOne::validateCommitments(std::vector<uint8_t>& messageVec,
        std::vector<std::vector<CryptoPP::Integer>>& shares,
        std::vector<std::vector<CryptoPP::Integer>>& randomness,
        std::vector<std::vector<std::array<uint8_t, 33>>>& commitments) {

    size_t sizeMsg1 = messageVec.size();
    // resize initialize all integers with zero
    std::vector<CryptoPP::Integer> S;
    S.resize(shares[0].size());

    // resize initialize all integers with zero
    std::vector<CryptoPP::Integer> R;
    R.resize(randomness[0].size());
    std::cout << randomness[0].size() << std::endl;

    for(int i=0; i<shares.size(); i++) {
        for(int j=0; j<shares[0].size(); j++) {
            S[j] += shares[i][j];
            R[j] += randomness[i][j];
        }
    }

    // reduce the S and R values using the order of the EC group
    for(int i=0; i<S.size(); i++) {
        S[i] = S[i].Modulo(curve.GetSubgroupOrder());
        R[i] = R[i].Modulo(curve.GetSubgroupOrder());
    }

    // reserve a vector for the commitment validation
    std::vector<CryptoPP::ECPPoint> C;
    C.reserve(commitments[0].size());

    // Init the vector with the commitment points of the first share
    for(int j=0; j<commitments[0].size(); j++) {
        CryptoPP::ECPPoint uncompressedPoint;
        curve.GetCurve().DecodePoint(uncompressedPoint, commitments[0][j].data(), 33);
        C.push_back(uncompressedPoint);
    }

    // Add up the remaining commitments
    for(int i=1; i<commitments.size(); i++) {
        for(int j=0; j<commitments[0].size(); j++) {
            CryptoPP::ECPPoint uncompressedPoint;
            curve.GetCurve().DecodePoint(uncompressedPoint, commitments[i][j].data(), 33);
            C[j] = curve.GetCurve().Add(C[j], uncompressedPoint);
        }
    }

    bool valid = true;
    for(int i=0; i<C.size() && valid; i++) {
        CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, R[i]);
        CryptoPP::ECPPoint xH = curve.GetCurve().ScalarMultiply(H, S[i]);
        CryptoPP::ECPPoint compC = curve.GetCurve().Add(rG, xH);

        if(compC.x != C[i].x || compC.y != C[i].y)
            valid = false;
    }
    if(valid)
        std::cout << "All commitments are valid" << std::endl;
    else
        std::cout << "Invalid commitment detected" << std::endl;

    std::cout << "Added Shares" << std::endl;
    std::vector<uint8_t> reconstructedMessage;
    reconstructedMessage.resize(sizeMsg1);

    for(int i=0; i < S.size(); i++) {
        size_t sliceSize = ((sizeMsg1 - 31*i > 31) ? 31 : sizeMsg1 - 31*i);
        S[i].Encode(&reconstructedMessage[31*i], sliceSize);
    }

    for(uint8_t c : reconstructedMessage) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    }
    std::cout << std::endl;
    std::cout << "Original" << std::endl;
    for(uint8_t c : messageVec)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    std::cout <<std::endl << std::endl;
    std::cout << "Done!" << std::endl;

}