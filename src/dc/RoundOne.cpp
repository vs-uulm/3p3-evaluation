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

    // TODO: for tests only
    srand(time(NULL));
    if(DCNetwork_.nodeID() % 3 == 0) {
        l = rand() % 128;
    }

    if (l > 0) {
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        uint16_t p = PRNG.GenerateWord32(0, 2*k_ - 1);

        // set the values in Big Endian format
        msgVector_[4*p]     = static_cast<uint8_t>((r & 0xFF00) >> 8);
        msgVector_[4*p + 1] = static_cast<uint8_t>((r & 0x00FF));
        msgVector_[4*p + 2] = static_cast<uint8_t>((l & 0xFF00) >> 8);
        msgVector_[4*p + 3] = static_cast<uint8_t>((l & 0x00FF));

        // generate k random K values used as seeds
        // for the commitments in the second round
        PRNG.GenerateBlock(&msgVector_[8*k_ + p * 32*k_], 32*k_);
    }

    // Split the message vector into slices of 31 Bytes
    size_t numSlices = std::ceil(msgVector_.size() / 31.0);
    std::vector<CryptoPP::Integer> msgSlices;
    msgSlices.reserve(numSlices);

    for(int i=0; i<numSlices; i++) {
        size_t sliceSize = ((msgVector_.size() - 31 * i > 31) ? 31 : msgVector_.size() - 31 * i);
        CryptoPP::Integer slice(&msgVector_[31 * i], sliceSize);
        msgSlices.push_back(std::move(slice));
    }

    // TODO remove
    // print the own message vector
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << std::dec << "Node: " << DCNetwork_.nodeID() << std::endl;
        for (uint8_t c: msgVector_) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c << " ";
        }
        std::cout << std::endl << std::endl;
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

    // generate and broadcast the commitments for the first round
    RoundOne::phaseOneTwo(shares, numSlices);

    // collect and validate the shares
    RoundOne::phaseThree(numSlices);

    // collect and validate the final shares
    RoundOne::phaseFour(numSlices);

    // transition to round two
    return std::make_unique<RoundTwo>(DCNetwork_);
}


void RoundOne::phaseOneTwo(std::vector<std::vector<CryptoPP::Integer>>& shares, size_t numSlices) {
    size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);

    std::vector<uint8_t> commitments;
    commitments.resize(k_ * numSlices * encodedPointSize);

    std::vector<std::vector<CryptoPP::Integer>> rVector;
    rVector.resize(k_);
    for(auto& slice : rVector)
        slice.reserve(numSlices);

    // init C
    C.resize(numSlices);

    // measure the time it takes to generate all the commitments
    auto start = std::chrono::high_resolution_clock::now();
    for(int i=0; i < k_; i++) {
        for(int j=0; j < numSlices; j++) {
            // generate the random value r for this slice of the share
            CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
            rVector[i].push_back(std::move(r));

            // generate the commitment for the j-th slice of the i-th share
            CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, rVector[i][j]);
            CryptoPP::ECPPoint xH = curve.GetCurve().ScalarMultiply(H, shares[i][j]);
            CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, xH);

            // compress the commitment and store in the given position in the vector
            size_t offset = (i * numSlices + j) * encodedPointSize;
            curve.GetCurve().EncodePoint(&commitments[offset], commitment, true);
            // store the commitment
            C[j] = curve.GetCurve().Add(C[j], commitment);
        }
    }

    // store the random values used for the Commitments of the own share
    R.resize(numSlices);
    // get the index of the own share by checking the position of the local nodeID in the member list
    int index = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
    for(int j=0; j<numSlices; j++) {
        R[j] = rVector[index][j];
    }

    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = finish - start;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Commitment generation finished in: " << duration.count() << "s" << std::endl;
    }

    // broadcast the commitments
    // TODO change to DC Network broadcast
    OutgoingMessage commitBroadcast(BROADCAST, CommitmentRoundOne, DCNetwork_.nodeID(), commitments);
    DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(commitBroadcast));

    // collect the commitments from the other k-1 members
    collectCommitments();

    // distribute the shares to the individual members
    for(auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
        int i = std::distance(DCNetwork_.members().begin(), it);

        if(it->second != SELF) {
            std::vector<uint8_t> rsPairs;
            rsPairs.resize(64 * numSlices);

            for (int j = 0; j < numSlices; j++) {
                rVector[i][j].Encode(&rsPairs[j*64], 32);
                shares[i][j].Encode(&rsPairs[j*64 + 32], 32);
            }

            OutgoingMessage rsMessage(it->second, SharingOneRoundOne, DCNetwork_.nodeID(), rsPairs);
            DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(rsMessage));
        }
    }

}

void RoundOne::phaseThree(size_t numSlices) {
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    bool validRound = validateCommitments();
    if(!validRound) {
        std::cout << "Invalid commitment detected" << std::endl;
    }
    std::vector<uint8_t> rsVector;
    rsVector.resize(numSlices*64);

    for(int i=0; i<numSlices; i++) {
        R[i].Encode(&rsVector[i*64], 32);
        S[i].Encode(&rsVector[i*64 + 32], 32);
    }

    // TODO change to DC Network Broadcast
    OutgoingMessage rsBroadcast(BROADCAST, SharingTwoRoundOne, DCNetwork_.nodeID(), rsVector);
    DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(rsBroadcast));
}

void RoundOne::phaseFour(size_t numSlices) {
    size_t remainingShares = k_-1;
    while(remainingShares > 0) {
        auto rsBroadcast = DCNetwork_.inbox().pop();

        if(rsBroadcast->msgType() != SharingTwoRoundOne) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "Inappropriate message received: " << (int) rsBroadcast->msgType() << std::endl;
            DCNetwork_.inbox().push(rsBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        } else {
            std::vector<uint8_t>& rsPairs = rsBroadcast->body();
            for(int i = 0; i < numSlices; i++) {
                CryptoPP::Integer r;
                CryptoPP::Integer s;
                // extract and decode the random values and the slice of the share
                r.Decode(&rsPairs[i*64], 32);
                s.Decode(&rsPairs[i*64 + 32], 32);

                R[i] += r;
                S[i] += s;
            }
        }
        remainingShares--;
    }

    // TODO validate commitments at this point if a blame message has been received
    for(int i=0; i<numSlices; i++) {
        R[i] = R[i].Modulo(curve.GetSubgroupOrder());
        S[i] = S[i].Modulo(curve.GetSubgroupOrder());
    }

    // reconstruct the original message
    std::vector<uint8_t> reconstructedMessage;
    reconstructedMessage.resize(msgVector_.size());
    for(int i=0; i < S.size(); i++) {
        size_t sliceSize = ((msgVector_.size() - 31*i > 31) ? 31 : msgVector_.size() - 31*i);
        S[i].Encode(&reconstructedMessage[31*i], sliceSize);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);

        std::cout << std::dec << "Node: " << DCNetwork_.nodeID() << std::endl;
        for(uint8_t c : reconstructedMessage) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c << " ";
        }

        std::cout << std::endl << std::endl;
    }
}


void RoundOne::collectCommitments() {
    while(commitments_.size() < k_-1) {
        auto commitBroadcast = DCNetwork_.inbox().pop();

        if (commitBroadcast->msgType() != CommitmentRoundOne) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "Inappropriate message received: " << (int) commitBroadcast->msgType() << std::endl;
            DCNetwork_.inbox().push(commitBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
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
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "All commitments received" << std::endl;
    }
}

bool RoundOne::validateCommitments() {
    size_t numSlices = S.size();
    size_t remainingShares = k_-1;
    while(remainingShares > 0) {
        auto rsMessage = DCNetwork_.inbox().pop();

        if(rsMessage->msgType() != SharingOneRoundOne) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "Inappropriate message received: " << (int) rsMessage->msgType() << std::endl;
            DCNetwork_.inbox().push(rsMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        } else {
            std::vector<uint8_t>& rsPairs = rsMessage->body();
            for (int i = 0; i < numSlices; i++) {
                CryptoPP::Integer r;
                CryptoPP::Integer s;
                // extract and decode the random values and the slice of the share
                r.Decode(&rsPairs[i*64], 32);
                s.Decode(&rsPairs[i*64 + 32], 32);

                CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, r);
                CryptoPP::ECPPoint xH = curve.GetCurve().ScalarMultiply(H, s);
                CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, xH);

                // verify that the commitment is valid
                if((commitment.x != commitments_[rsMessage->senderID()][DCNetwork_.nodeID()][i].x)
                    || (commitment.y != commitments_[rsMessage->senderID()][DCNetwork_.nodeID()][i].y)) {
                    // TODO inject blame message
                    return false;
                }

                R[i] += r;
                S[i] += s;
                C[i] = curve.GetCurve().Add(C[i], commitment);
            }
        }
        remainingShares--;
    }

    // reduce R and S
    for(int i=0; i<numSlices; i++) {
        R[i] = R[i].Modulo(curve.GetSubgroupOrder());
        S[i] = S[i].Modulo(curve.GetSubgroupOrder());
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "All commitments are valid" << std::endl;
    }
    return true;
}




































