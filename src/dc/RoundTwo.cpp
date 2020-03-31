#include <iostream>
#include <cryptopp/oids.h>
#include <thread>
#include <iomanip>
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
          slots_(std::move(slots)),
          seeds_(std::move(seeds)), rValues_(k_) {

    curve.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));

    R.resize(slots_.size());
    for(uint32_t slot = 0; slot < slots_.size(); slot++)
        R[slot].resize(slots_[slot]);

    // pre-compute the pseudo random r values
    for (uint32_t member = 0; member < k_; member++) {
        rValues_[member].resize(slots_.size());

        for (uint32_t slot = 0; slot < slots_.size(); slot++) {

            rValues_[member][slot].resize(k_);
            DRNG.SetKeyWithIV(seeds_[slot][member].data(), 16, seeds_[slot][member].data() + 16, 16);

            size_t numSlices = std::ceil(slots_[slot] / 31.0);
            for (uint32_t share = 0; share < k_; share++) {
                rValues_[member][slot][share].reserve(numSlices);

                for (uint32_t slice = 0; slice < numSlices; slice++) {
                    CryptoPP::Integer r(DRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                    rValues_[member][slot][share].push_back(std::move(r));

                    R[slot][slice] += r;
                }
            }
        }
    }

    for(uint32_t slot = 0; slot < slots_.size(); slot++) {
        for(uint32_t slice = 0; slice < slots_[slot]; slice++) {
            R[slot][slice] = R[slot][slice].Modulo(curve.GetSubgroupOrder());
        }
    }
}

RoundTwo::~RoundTwo() {}

std::unique_ptr<DCState> RoundTwo::executeTask() {
    size_t numSlots = slots_.size();

    std::vector<size_t> numSlices;
    numSlices.reserve(numSlots);
    // determine the number of slices for each slot individually
    for (uint32_t i = 0; i < numSlots; i++)
        numSlices.push_back(std::ceil(slots_[i] / 31.0));

    std::vector<uint8_t> submittedMessage;
    std::vector<CryptoPP::Integer> messageSlices;

    if (slotIndex_ > -1) {
        submittedMessage = DCNetwork_.submittedMessages().front();
        DCNetwork_.submittedMessages().pop();

        // Split the submitted message into slices of 31 Bytes
        messageSlices.reserve(numSlices[slotIndex_]);

        for (uint32_t i = 0; i < numSlices[slotIndex_]; i++) {
            size_t sliceSize = ((submittedMessage.size() - 31 * i > 31) ? 31 : submittedMessage.size() - 31 * i);
            CryptoPP::Integer slice(&submittedMessage[31 * i], sliceSize);
            messageSlices.push_back(std::move(slice));
        }
    }

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> shares;
    shares.resize(numSlots);
    for (uint32_t slot = 0; slot < numSlots; slot++) {
        shares[slot].resize(k_);

        // initialize the slices of the k-th share with zeroes
        // except the slices of the own message slot
        if (slotIndex_ == slot) {
            for (uint32_t slice = 0; slice < numSlices[slot]; slice++)
                shares[slot][k_ - 1].push_back(messageSlices[slice]);
        } else {
            for (uint32_t slice = 0; slice < numSlices[slot]; slice++)
                shares[slot][k_ - 1].push_back(CryptoPP::Integer::Zero());
        }

        // fill the first slices of the first k-1 shares with random values
        // and subtract the values from the corresponding slices in the k-th share
        for (uint32_t share = 0; share < k_ - 1; share++) {
            shares[slot][share].reserve(numSlices[slot]);

            for (uint32_t slice = 0; slice < numSlices[slot]; slice++) {
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                // subtract the value from the corresponding slice in the k-th share
                shares[slot][k_ - 1][slice] -= r;
                // store the random value in the slice of this share
                shares[slot][share].push_back(std::move(r));
            }
        }

        // reduce the slices in the k-th share
        for (uint32_t slice = 0; slice < numSlices[slot]; slice++)
            shares[slot][k_ - 1][slice] = shares[slot][k_ - 1][slice].Modulo(curve.GetSubgroupOrder());
    }

    // initialize the slices in the slots of the final share with the slices of the own share
    S.resize(numSlots);

    for(uint32_t slot = 0; slot < numSlots; slot++) {
        S[slot].reserve(numSlices[slot]);

        for(uint32_t slice = 0; slice < numSlices[slot]; slice++)
            S[slot].push_back(shares[slot][nodeIndex_][slice]);
    }

    // determine the total number of slices
    size_t totalNumSlices = 0;
    for(auto& slot : shares)
        totalNumSlices += slot.size();


    RoundTwo::sharingPartOne(totalNumSlices, shares);

    RoundTwo::sharingPartTwo(totalNumSlices);

    std::vector<std::vector<uint8_t>> messages = RoundTwo::resultComputation();

    return std::make_unique<Init>(DCNetwork_);
}

void RoundTwo::sharingPartOne(size_t totalNumSlices, std::vector<std::vector<std::vector<CryptoPP::Integer>>> &shares) {
    size_t numSlots = slots_.size();

    if (securedRound_) {
        C.resize(shares.size());

        size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);
        std::vector<uint8_t> commitmentVector(k_ * totalNumSlices * encodedPointSize);

        std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitments;
        commitments.reserve(numSlots);
        for(uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
            size_t numSlices = shares[slot][0].size();

            std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
            commitmentMatrix.resize(k_);
            for(auto& share : commitmentMatrix)
                share.reserve(numSlices);

            C[slot].resize(numSlices);

            for(uint32_t share = 0; share < k_; share++) {
                for(uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {

                    // generate the commitment for the j-th slice of the i-th share
                    CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G,
                                                                            rValues_[nodeIndex_][slot][share][slice]);
                    CryptoPP::ECPPoint xH = curve.GetCurve().ScalarMultiply(H, shares[slot][share][slice]);
                    CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, xH);

                    // Add the commitment to the sum C
                    C[slot][slice] = curve.GetCurve().Add(C[slot][slice], commitment);

                    // store the commitment
                    commitmentMatrix[share].push_back(std::move(commitment));

                    // compress the commitment and store in the given position in the vector
                    curve.GetCurve().EncodePoint(&commitmentVector[offset], commitmentMatrix[share][slice], true);
                }
            }
            commitments.push_back(std::move(commitmentMatrix));

        }
        commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitments)));

        // broadcast the commitments
        for(auto& member : DCNetwork_.members()) {
            if(member.second != SELF) {
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
                commitments.reserve(numSlots);

                // decompress all the points
                for(uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                    size_t numSlices = shares[slot][0].size();

                    std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix(k_);
                    for(auto& share : commitmentMatrix)
                        share.reserve(numSlices);

                    for(uint32_t share = 0; share < k_; share++) {
                        for(uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {
                            CryptoPP::ECPPoint commitment;
                            curve.GetCurve().DecodePoint(commitment, &commitBroadcast->body()[offset],
                                                         encodedPointSize);

                            C[slot][slice] = curve.GetCurve().Add(C[slot][slice], commitment);
                            commitmentMatrix[share].push_back(std::move(commitment));
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
        uint32_t shareIndex = std::distance(DCNetwork_.members().begin(), it);

        if(it->second != SELF) {
            std::vector<uint8_t> sharingMessage(32 * totalNumSlices);

            for(uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                size_t numSlices = shares[slot][shareIndex].size();

                for(uint32_t slice = 0; slice < numSlices; slice++, offset += 32)
                    shares[slot][shareIndex][slice].Encode(&sharingMessage[offset], 32);
            }

            OutgoingMessage rsMessage(it->second, RoundTwoSharingPartOne, DCNetwork_.nodeID(), sharingMessage);
            DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(rsMessage));
        }
    }
}

void RoundTwo::sharingPartTwo(size_t totalNumSlices) {
    size_t numSlots = slots_.size();

    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    for (uint32_t remainingShares = k_-1; remainingShares > 0; remainingShares--) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage->msgType() != RoundTwoSharingPartOne) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "Inappropriate message received: " << (int) sharingMessage->msgType() << std::endl;
            DCNetwork_.inbox().push(sharingMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        } else {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                 DCNetwork_.members().find(sharingMessage->senderID()));

            for(uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                size_t numSlices = S[slot].size();

                for(uint32_t slice = 0; slice < numSlices; slice++, offset += 32) {
                    CryptoPP::Integer s(&sharingMessage->body()[offset], 32);

                    if(securedRound_) {
                        CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G,rValues_[memberIndex][slot][DCNetwork_.nodeID()][slice]);
                        CryptoPP::ECPPoint xH = curve.GetCurve().ScalarMultiply(H, s);
                        CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, xH);

                        // verify that the commitment is valid
                        if((commitment.x != commitments_[sharingMessage->senderID()][slot][DCNetwork_.nodeID()][slice].x)
                            || (commitment.y != commitments_[sharingMessage->senderID()][slot][DCNetwork_.nodeID()][slice].y)) {

                            // TODO inject blame message
                            std::lock_guard<std::mutex> lock(mutex_);
                            std::cout << "Invalid commitment detected" << std::endl;
                            break;
                        }
                    }
                    S[slot][slice] += s;
                }
            }
        }
    }

    // construct the sharing broadcast which includes the added shares
    std::vector<uint8_t> sharingBroadcast(totalNumSlices * 32);
    for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
        for (uint32_t slice = 0; slice < S[slot].size(); slice++, offset += 32) {
            S[slot][slice] = S[slot][slice].Modulo(curve.GetSubgroupOrder());
            S[slot][slice].Encode(&sharingBroadcast[offset], 32);
        }
    }

    // Broadcast the added shares in the DC network
    for (auto &member : DCNetwork_.members()) {
        if (member.second != SELF) {
            OutgoingMessage rsBroadcast(member.second, RoundOneSharingPartTwo, DCNetwork_.nodeID(), sharingBroadcast);
            DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(rsBroadcast));
        }
    }
}

std::vector<std::vector<uint8_t>> RoundTwo::resultComputation() {
    size_t numSlots = S.size();
    for (uint32_t remainingShares = k_-1; remainingShares > 0; remainingShares--) {
        auto sharingBroadcast = DCNetwork_.inbox().pop();

        if (sharingBroadcast->msgType() != RoundOneSharingPartTwo) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "Inappropriate message received: " << (int) sharingBroadcast->msgType() << std::endl;
            DCNetwork_.inbox().push(sharingBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        } else {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                 DCNetwork_.members().find(sharingBroadcast->senderID()));

            for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                for (uint32_t slice = 0; slice < S[slot].size(); slice++, offset += 32) {

                    CryptoPP::Integer S_(&sharingBroadcast->body()[offset], 32);
                    S[slot][slice] += S_;

                    if(securedRound_) {
                        CryptoPP::ECPPoint C_;
                        for (auto &c : commitments_)
                            C_ = curve.GetCurve().Add(C_, c.second[slot][memberIndex][slice]);

                        CryptoPP::Integer R_;
                        for (auto &r : rValues_)
                            R_ += r[slot][memberIndex][slice];
                        R_ = R_.Modulo(curve.GetSubgroupOrder());

                        CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, R_);
                        CryptoPP::ECPPoint sH = curve.GetCurve().ScalarMultiply(H, S_);
                        CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, sH);

                        if ((commitment.x != C_.x) || (commitment.y != C_.y)) {
                            // TODO inject blame message

                            std::lock_guard<std::mutex> lock(mutex_);
                            std::cout << "Invalid commitment detected" << std::endl;
                            break;
                        }
                    }
                }
            }
        }
    }

    // final commitment validation
    if (securedRound_) {
        for (uint32_t slot = 0; slot < numSlots; slot++) {
            for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
                S[slot][slice] = S[slot][slice].Modulo(curve.GetSubgroupOrder());

                CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, R[slot][slice]);
                CryptoPP::ECPPoint sH = curve.GetCurve().ScalarMultiply(H, S[slot][slice]);
                CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, sH);

                if ((C[slot][slice].x != commitment.x) || (C[slot][slice].y != commitment.y)) {
                    std::cout << "Invalid commitment detected" << std::endl;
                    break;
                }
            }
        }
    } else {
        for (uint32_t slot = 0; slot < numSlots; slot++) {
            for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
                S[slot][slice] = S[slot][slice].Modulo(curve.GetSubgroupOrder());
            }
        }
    }

    // reconstruct the original message
    std::vector<std::vector<uint8_t>> reconstructedMessageSlots(numSlots);
    for (uint32_t slot = 0; slot < numSlots; slot++) {
        reconstructedMessageSlots[slot].resize(slots_[slot]);

        for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
            size_t sliceSize = ((slots_[slot] - 31 * slice > 31) ? 31 : slots_[slot] - 31 * slice);
            S[slot][slice].Encode(&reconstructedMessageSlots[slot][31 * slice], sliceSize);
        }
    }

    // print the reconstructed message slots
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Node: " << DCNetwork_.nodeID() << std::endl;
        for (auto &slot : reconstructedMessageSlots) {
            std::cout << "|";
            for (uint8_t c : slot) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
            }
            std::cout << "|" << std::endl;
        }
    }

    return reconstructedMessageSlots;
}












