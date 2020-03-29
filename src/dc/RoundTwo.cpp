#include <iostream>
#include <cryptopp/oids.h>
#include <thread>
#include "RoundTwo.h"
#include "Init.h"
#include "../datastruct/MessageType.h"
#include "RoundOne.h"

// constructor for a unsecured round
RoundTwo::RoundTwo(DCNetwork &DCNet, int slotIndex, std::vector<uint16_t> &slots)
        : DCNetwork_(DCNet), k_(DCNetwork_.members().size()), securedRound_(false), slotIndex_(slotIndex),
          slots_(std::move(slots)) {
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

// constructor for a secured round
RoundTwo::RoundTwo(DCNetwork &DCNet, int slotIndex, std::vector<uint16_t> &slots,
                   std::vector<std::vector<std::array<uint8_t, 32>>> &seeds)
        : DCNetwork_(DCNet), k_(DCNetwork_.members().size()), securedRound_(true), slotIndex_(slotIndex),
          slots_(std::move(slots)), seeds_(std::move(seeds)) {
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}


RoundTwo::~RoundTwo() {

}

std::unique_ptr<DCState> RoundTwo::executeTask() {
    size_t numSlots = slots_.size();

    std::vector<size_t> numSlices;
    numSlices.reserve(numSlots);
    // determine the number of slices for each slot individually
    for (int i = 0; i < numSlots; i++) {
        numSlices.push_back(std::ceil(slots_[i] / 31.0));
    }

    std::vector<uint8_t> submittedMessage;
    std::vector<CryptoPP::Integer> messageSlices;

    if (slotIndex_ > -1) {
        submittedMessage = DCNetwork_.submittedMessages().front();
        DCNetwork_.submittedMessages().pop();

        // Split the submitted message into slices of 31 Bytes
        messageSlices.reserve(numSlices[slotIndex_]);

        for (int i = 0; i < numSlices[slotIndex_]; i++) {
            size_t sliceSize = ((submittedMessage.size() - 31 * i > 31) ? 31 : submittedMessage.size() - 31 * i);
            CryptoPP::Integer slice(&submittedMessage[31 * i], sliceSize);
            messageSlices.push_back(std::move(slice));
        }
    }

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> shares;
    shares.resize(numSlots);
    for (int slot = 0; slot < numSlots; slot++) {
        shares[slot].resize(k_);

        // initialize the slices of the k-th share with zeroes
        // except the slices of the own message slot
        if (slotIndex_ == slot) {
            for (int slice = 0; slice < numSlices[slot]; slice++) {
                shares[slot][k_ - 1].push_back(messageSlices[slice]);
            }
        } else {
            for (int slice = 0; slice < numSlices[slot]; slice++) {
                shares[slot][k_ - 1].push_back(CryptoPP::Integer::Zero());
            }
        }

        // fill the first slices of the first k-1 shares with random values
        // and subtract the values from the corresponding slices in the k-th share
        for (int share = 0; share < k_ - 1; share++) {
            shares[slot][share].reserve(numSlices[slot]);
            for (int slice = 0; slice < numSlices[slot]; slice++) {
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                // subtract the value from the corresponding slice in the k-th share
                shares[slot][k_ - 1][slice] -= r;
                // store the random value in the slice of this share
                shares[slot][share].push_back(std::move(r));
            }
        }

        // reduce the slices in the k-th share
        for (int slice = 0; slice < numSlices[slot]; slice++) {
            shares[slot][k_ - 1][slice] = shares[slot][k_ - 1][slice].Modulo(curve.GetSubgroupOrder());
        }
    }

    // initialize the slices in the slots of the final share with the slices of the own share
    S.resize(numSlots);

    for (int slot = 0; slot < numSlots; slot++) {
        S[slot].reserve(numSlices[slot]);

        for (int slice = 0; slice < numSlices[slot]; slice++) {
            S[slot].push_back(shares[slot][nodeIndex_][slice]);
        }
    }


    RoundTwo::sharingPartOne(shares);


    return std::make_unique<Init>(DCNetwork_);
}

void RoundTwo::sharingPartOne(std::vector<std::vector<std::vector<CryptoPP::Integer>>> &shares) {
    size_t numSlots = slots_.size();

    // determine the total number of slices
    size_t totalNumSlices = 0;
    for (auto &slot : shares)
        totalNumSlices += slot.size();

    if (securedRound_) {
        C.resize(shares.size());
        R.resize(shares.size());

        size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);
        std::vector<uint8_t> commitmentVector(k_ * totalNumSlices * encodedPointSize);

        std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitments(numSlots);
        std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues(numSlots);
        for (int slot = 0; slot < numSlots; slot++) {
            size_t numSlices = shares[slot][0].size();

            std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
            commitmentMatrix.resize(k_);
            for (auto &share : commitmentMatrix)
                share.reserve(numSlices);

            rValues[slot].resize(k_);
            C[slot].resize(numSlices);

            // use 16 bytes as key and 16 bytes as IV
            DRNG.SetKeyWithIV(seeds_[slot][nodeIndex_].data(), 16, seeds_[slot][nodeIndex_].data() + 16, 16);
            for (int share = 0; share < k_; share++) {
                for (int slice = 0; slice < numSlices; slice++) {
                    // generate the random value r for this slice of the share
                    CryptoPP::Integer r(DRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                    rValues[slot][share].push_back(std::move(r));

                    // generate the commitment for the j-th slice of the i-th share
                    CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, rValues[slot][share][slice]);
                    CryptoPP::ECPPoint xH = curve.GetCurve().ScalarMultiply(H, shares[slot][share][slice]);
                    CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, xH);

                    // store the commitment
                    commitmentMatrix[share].push_back(std::move(commitment));

                    // compress the commitment and store in the given position in the vector
                    size_t offset = (share * numSlices + slice) * encodedPointSize;
                    curve.GetCurve().EncodePoint(&commitmentVector[offset], commitmentMatrix[share][slice], true);
                    // Add the commitment to the sum C
                    C[slot][slice] = curve.GetCurve().Add(C[slot][slice], commitmentMatrix[share][slice]);
                }
            }
            commitments.push_back(std::move(commitmentMatrix));

            R[slot].reserve(shares[slot].size());
            for (int slice = 0; slice < numSlices; slice++) {
                R[slot].push_back(rValues[slot][nodeIndex_][slice]);
            }
        }
        commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitments)));

        // broadcast the commitments
        for (auto &member : DCNetwork_.members()) {
            if (member.second != SELF) {
                OutgoingMessage commitBroadcast(member.second, CommitmentRoundTwo, DCNetwork_.nodeID(),
                                                commitmentVector);
                DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(commitBroadcast));
            }
        }

        // collect the commitments from the other k-1 members
        while (commitments_.size() < k_) {
            auto commitBroadcast = DCNetwork_.inbox().pop();

            if (commitBroadcast->msgType() != CommitmentRoundTwo) {
                std::lock_guard<std::mutex> lock(mutex_);
                std::cout << "Inappropriate message received: " << (int) commitBroadcast->msgType() << std::endl;
                DCNetwork_.inbox().push(commitBroadcast);
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            } else {
                size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);

                std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitments;
                commitments.resize(numSlots);

                // decompress all the points
                for(int slot=0; slot<numSlots; slot++) {
                    size_t numSlices = shares[slot][0].size();
                    std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix(k_);
                    for (auto &share : commitmentMatrix)
                        share.reserve(numSlices);
                    for (int share = 0; share < k_; share++) {
                        for (int slice = 0; slice < numSlices; slice++) {
                            size_t offset = (share * numSlices + slice) * encodedPointSize;
                            CryptoPP::ECPPoint commitment;
                            curve.GetCurve().DecodePoint(commitment, &commitBroadcast->body()[offset],
                                                         encodedPointSize);
                            commitmentMatrix[share].push_back(std::move(commitment));

                            C[slot][slice] = curve.GetCurve().Add(C[slot][slice], commitment);
                        }
                    }
                    commitments.push_back(std::move(commitmentMatrix));
                }
                // Store the decompressed points
                commitments_.insert(std::pair(commitBroadcast->senderID(), std::move(commitments)));
            }
        }
    }

    // distribute the shares to the individual members
    for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
        int shareIndex = std::distance(DCNetwork_.members().begin(), it);

        if (it->second != SELF) {
            std::vector<uint8_t> sharingMessage(32 * totalNumSlices);

            for (int slot = 0; slot < numSlots; slot++) {
                size_t numSlices = shares[slot][shareIndex].size();
                for(int slice=0; slice < numSlices; slice++) {
                    size_t offset = (slot * numSlices + slice) * 32;
                    shares[slot][shareIndex][slice].Encode(&sharingMessage[offset], 32);
                }
            }

            OutgoingMessage rsMessage(it->second, RoundTwoSharingPartOne, DCNetwork_.nodeID(), sharingMessage);
            DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(rsMessage));
        }
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Finished" << std::endl;
    }
}