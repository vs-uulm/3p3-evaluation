#include <iostream>
#include <thread>
#include <cryptopp/oids.h>
#include <iomanip>
#include "RoundOne.h"
#include "Init.h"
#include "RoundTwo.h"
#include "../datastruct/MessageType.h"

std::mutex mutex_;

RoundOne::RoundOne(DCNetwork& DCNet) : DCNetwork_(DCNet) {
    curve.Initialize(CryptoPP::ASN1::secp256k1());
    k_ = DCNetwork_.members().size();
    // TODO undo
    //k_ = 8;
    msgVector_.resize(2*k_ * (4 + 32*k_));
}

RoundOne::~RoundOne() {}

std::unique_ptr<DCState> RoundOne::executeTask() {
    // check if there is a submitted message
    // and determine it's length
    uint16_t l = 0;
    if (!DCNetwork_.submittedMessages().empty()) {
        size_t msgSize = DCNetwork_.submittedMessages().front().size();
        // ensure that the message size does not exceed 2^16 Bytes
        l = msgSize > USHRT_MAX ? USHRT_MAX : msgSize;
    }

    // TODO for tests only
    l = 32;

    if (l > 0) {
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        uint16_t p = PRNG.GenerateWord32(0, 2*k_ - 1);

        // set the values in Big Endian format
        msgVector_[4*p] = static_cast<uint8_t>((r & 0xFF00) >> 8);
        msgVector_[4*p + 1] = static_cast<uint8_t>((r & 0x00FF));
        msgVector_[4*p + 2] = static_cast<uint8_t>((l & 0xFF00) >> 8);
        msgVector_[4*p + 3] = static_cast<uint8_t>((l & 0x00FF));

        // generate k random K values used as seeds
        // for the commitments of the second round
        PRNG.GenerateBlock(&msgVector_[8*k_ + p * 32*k_], 32*k_);
    }

    // Split the message vector into slices of 31 Bytes
    size_t numSlices = std::ceil(msgVector_.size() / 31.0);
    S.reserve(numSlices);

    for(int i=0; i<numSlices; i++) {
        size_t sliceSize = ((msgVector_.size() - 31*i > 31) ? 31 : msgVector_.size() - 31*i);
        CryptoPP::Integer slice(&msgVector_[31*i], sliceSize);
        S.push_back(std::move(slice));
    }

    // Split each slice into k shares
    std::vector<std::vector<CryptoPP::Integer>> shares;
    shares.resize(k_);
    // init the k-th set of shares with zeroes
    shares[k_-1].resize(numSlices);
    // fill the first k-1 set of shares with random data
    for(int i=0; i<k_-1; i++) {
        shares[i].reserve(numSlices);
        for(int j=0; j<numSlices; j++) {
            CryptoPP::Integer slot(PRNG, Integer::One(), curve.GetMaxExponent());
            shares[k_-1][j] -= slot;
            shares[i].push_back(std::move(slot));
        }
    }
    // calculate the k-th share
    for (int j = 0; j < numSlices; j++) {
        shares[k_-1][j] += S[j];
        shares[k_-1][j] = shares[k_-1][j].Modulo(curve.GetSubgroupOrder());
    }

    // generate and broadcast the commitments for the first round
    phaseOne(shares);

    // transition to round two
    return std::make_unique<RoundTwo>(DCNetwork_);
}



void RoundOne::phaseOne(std::vector<std::vector<CryptoPP::Integer>>& shares) {
    size_t numSlices = S.size();
    size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);

    std::vector<uint8_t> commitments;
    commitments.resize(k_ * numSlices * encodedPointSize);

    std::vector<std::vector<CryptoPP::Integer>> randomness;
    randomness.resize(k_);
    for(auto& slice : randomness)
        slice.reserve(numSlices);

    // init R and C
    R.resize(numSlices);
    C.resize(numSlices);

    // measure the time it takes to generate all the commitments
    auto start = std::chrono::high_resolution_clock::now();
    for(int i=0; i < k_; i++) {
        for (int j=0; j < numSlices; j++) {
            // generate the randomness r for this slice of the share
            CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
            R[j] += r;
            randomness[i].push_back(std::move(r));

            // generate the commitment for the j-th slice of the i-th share
            CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, randomness[i][j]);
            CryptoPP::ECPPoint xH = curve.GetCurve().ScalarMultiply(H, shares[i][j]);
            CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, xH);

            // compress the commitment and store in the given position in the vector
            size_t offset = (i * numSlices + j) * encodedPointSize;
            curve.GetCurve().EncodePoint(&commitments[offset], commitment, true);
            // store the commitment
            C[j] = curve.GetCurve().Add(C[j], commitment);
        }
    }

    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = finish - start;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Commitment generation finished in: " << duration.count() << std::endl;
    }

    // TODO change to DC internal broadcast
    OutgoingMessage commitBroadcast(BROADCAST, CommitmentRoundOne, DCNetwork_.nodeID(), commitments);
    DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(commitBroadcast));

    bool valid = processCommitments();
    //std::vector<std::vector<std::array<uint8_t, 33>>> commitmentsTest;
    //validateCommitments(shares, commitmentsTest);
}

bool RoundOne::processCommitments() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Waiting for commitments" << std::endl;
    }
    size_t remainingCommitments = k_ -1;
    while(remainingCommitments > 0) {
        auto commitBroadcast = DCNetwork_.inbox().pop();

        if (commitBroadcast->msgType() != CommitmentRoundOne) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "Inappropriate message received: " << (int) commitBroadcast->msgType() << std::endl;
        } else {
            // extract and store the commitments
            std::vector<uint8_t>& commitments = commitBroadcast->body();
            size_t numSlices = S.size();
            size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);

            std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
            commitmentMatrix.resize(k_);
            for(auto& share : commitmentMatrix)
                share.reserve(numSlices);

            // decompress all the points
            for(int i=0; i < k_; i++) {
                for (int j = 0; j < numSlices; j++) {
                    size_t offset = (i * numSlices + j) * encodedPointSize;
                    CryptoPP::ECPPoint commitment;
                    curve.GetCurve().DecodePoint(commitment, &commitments[offset], encodedPointSize);
                    commitmentMatrix[i].push_back(std::move(commitment));
                }
            }
            // Store the decompressed points
            commitments_.insert(std::pair(commitBroadcast->senderID(), std::move(commitmentMatrix)));
        }
        remainingCommitments--;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "All commitments received" << std::endl;
    }
}



void RoundOne::validateCommitments(std::vector<std::vector<CryptoPP::Integer>>& shares,
        std::vector<std::vector<std::array<uint8_t, 33>>>& commitments) {

    // TODO redo

    // initialize the slices with zeroes
    std::vector<CryptoPP::Integer> S;
    S.resize(shares[0].size());

    for(int i=0; i<shares.size(); i++) {
        for(int j=0; j<shares[0].size(); j++) {
            S[j] += shares[i][j];
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
    reconstructedMessage.resize(msgVector_.size());

    for(int i=0; i < S.size(); i++) {
        size_t sliceSize = ((msgVector_.size() - 31*i > 31) ? 31 : msgVector_.size() - 31*i);
        S[i].Encode(&reconstructedMessage[31*i], sliceSize);
    }

    for(uint8_t c : reconstructedMessage) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    }
    std::cout << std::endl;
    std::cout << "Original" << std::endl;
    for(uint8_t c : msgVector_)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    std::cout <<std::endl << std::endl;
    std::cout << "Done!" << std::endl;
}



































