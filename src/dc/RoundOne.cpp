#include <iostream>
#include <thread>
#include <cryptopp/oids.h>
#include <iomanip>
#include "RoundOne.h"
#include "Init.h"
#include "RoundTwo.h"
#include "../datastruct/MessageType.h"
#include "Ready.h"

std::mutex mutex_;

RoundOne::RoundOne(DCNetwork &DCNet, bool securedRound)
        : DCNetwork_(DCNet), securedRound_(securedRound), k_(DCNetwork_.k()) {
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));

    if (securedRound_)
        msgVector_.resize(2 * k_ * (4 + 32 * k_));
    else
        msgVector_.resize(8 * k_);
}

RoundOne::~RoundOne() {}

std::unique_ptr<DCState> RoundOne::executeTask() {
    // check if there is a submitted message and determine it's length,
    // but don't remove it from the message queue just yet
    uint16_t l = 0;
    if (!DCNetwork_.submittedMessages().empty()) {
        size_t msgSize = DCNetwork_.submittedMessages().front().size();
        // ensure that the message size does not exceed 2^16 Bytes
        l = msgSize > USHRT_MAX ? USHRT_MAX : msgSize;

        // for tests only
        // print the submitted message
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Message submitted by node " << DCNetwork_.nodeID() << ":" << std::endl;
        for (uint8_t c : DCNetwork_.submittedMessages().front()) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
        }
        std::cout << std::endl << std::endl;
    } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    int p = -1;
    if (l > 0) {
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        p = PRNG.GenerateWord32(0, 2 * k_ - 1);

        // set the values in Big Endian format
        msgVector_[4 * p] = static_cast<uint8_t>((r & 0xFF00) >> 8);
        msgVector_[4 * p + 1] = static_cast<uint8_t>((r & 0x00FF));
        msgVector_[4 * p + 2] = static_cast<uint8_t>((l & 0xFF00) >> 8);
        msgVector_[4 * p + 3] = static_cast<uint8_t>((l & 0x00FF));

        // generate k random K values used as seeds
        // for the commitments in the second round
        if (securedRound_)
            PRNG.GenerateBlock(&msgVector_[8 * k_ + p * 32 * k_], 32 * k_);
    }

    // Split the message vector into slices of 31 Bytes
    size_t numSlices = std::ceil(msgVector_.size() / 31.0);
    std::vector<CryptoPP::Integer> msgSlices;
    msgSlices.reserve(numSlices);

    for (uint32_t i = 0; i < numSlices; i++) {
        size_t sliceSize = ((msgVector_.size() - 31 * i > 31) ? 31 : msgVector_.size() - 31 * i);
        CryptoPP::Integer slice(&msgVector_[31 * i], sliceSize);
        msgSlices.push_back(std::move(slice));
    }

    RoundOne::printMessageVector(msgVector_);

    // Split each slice into k shares
    std::vector<std::vector<CryptoPP::Integer>> shares;
    shares.resize(k_);

    // initialize the slices of the k-th share with zeroes
    shares[k_ - 1].resize(numSlices);

    // fill the first k-1 set of shares with random data
    for (uint32_t i = 0; i < k_ - 1; i++) {
        shares[i].reserve(numSlices);
        for (uint32_t j = 0; j < numSlices; j++) {
            CryptoPP::Integer slice(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
            shares[k_ - 1][j] -= slice;
            shares[i].push_back(std::move(slice));
        }
    }

    // calculate the k-th share
    for (uint32_t j = 0; j < numSlices; j++) {
        shares[k_ - 1][j] += msgSlices[j];
        shares[k_ - 1][j] = shares[k_ - 1][j].Modulo(curve.GetSubgroupOrder());
    }

    // store the slices of the own share in S
    S.resize(numSlices);

    for (uint32_t j = 0; j < numSlices; j++)
        S[j] = shares[nodeIndex_][j];

    // generate and broadcast the commitments for the first round
    RoundOne::sharingPartOne(shares);

    // collect and validate the shares
    int result = RoundOne::sharingPartTwo();
    // a blame message has been received
    if(result < 0) {
        // TODO clean up the inbox
        return std::make_unique<Init>(DCNetwork_);
    }

    // collect and validate the final shares
    std::vector<uint8_t> finalMessageVector = RoundOne::resultComputation();

    if (p > -1) {
        // verify that no collision occurred
        if ((msgVector_[4 * p] != finalMessageVector[4 * p]) ||
            (msgVector_[4 * p + 1] != finalMessageVector[4 * p + 1])) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "A collision occurred at position: " << std::dec << p + 1 << std::endl;
            // TODO handle the collision
        }
    }

    // prepare round two
    std::vector<uint16_t> slots;
    std::vector<std::vector<std::array<uint8_t, 32>>> seeds;
    // determine the non-empty slots in the message vector
    // and calculate the index of the own slot if present
    int slotIndex = -1;
    for (uint32_t i = 0; i < 2 * k_; i++) {
        if (p == i) {
            slotIndex = slots.size();
        }
        uint16_t slotSize = (finalMessageVector[4 * i + 2] << 8) | finalMessageVector[4 * i + 3];
        if (slotSize > 0) {
            // extract the seeds for the corresponding slot
            std::vector<std::array<uint8_t, 32>> K;
            K.reserve(k_);
            for (uint32_t j = 0; j < k_; j++) {
                std::array<uint8_t, 32> K_;
                std::copy(&finalMessageVector[8 * k_ + 32 * j], &finalMessageVector[8 * k_ + 32 * j] + 32, K_.data());
                K.push_back(std::move(K_));
            }
            seeds.push_back(std::move(K));

            // store the size of the slot along with the seed
            slots.push_back(slotSize);
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    // if no member wants to send a message, return to the Ready state

    if (slots.size() == 0) {
        return std::make_unique<Ready>(DCNetwork_);
    } else {
        if (securedRound_)
            return std::make_unique<RoundTwo>(DCNetwork_, slotIndex, slots, seeds);
        else
            return std::make_unique<RoundTwo>(DCNetwork_, slotIndex, slots);
    }
}

void RoundOne::sharingPartOne(std::vector<std::vector<CryptoPP::Integer>> &shares) {
    size_t numSlices = shares[0].size();
    std::vector<std::vector<CryptoPP::Integer>> rValues;
    if (securedRound_) {
        size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);

        std::vector<uint8_t> commitments;
        commitments.resize(k_ * numSlices * encodedPointSize);

        rValues.resize(k_);
        for (auto &slice : rValues)
            slice.reserve(numSlices);

        // init C
        C.resize(numSlices);

        std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
        commitmentMatrix.resize(k_);
        for (auto &share : commitmentMatrix)
            share.reserve(numSlices);

        // measure the time it takes to generate all the commitments
        auto start = std::chrono::high_resolution_clock::now();
        for (uint32_t share = 0; share < k_; share++) {
            for (uint32_t slice = 0; slice < numSlices; slice++) {
                // generate the random value r for this slice of the share
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                rValues[share].push_back(std::move(r));

                // generate the commitment for the j-th slice of the i-th share
                CryptoPP::ECPPoint commitment = commit(rValues[share][slice], shares[share][slice]);

                // store the commitment
                commitmentMatrix[share].push_back(std::move(commitment));

                // compress the commitment and store in the given position in the vector
                size_t offset = (share * numSlices + slice) * encodedPointSize;
                curve.GetCurve().EncodePoint(&commitments[offset], commitmentMatrix[share][slice], true);

                // Add the commitment to the sum C
                C[slice] = curve.GetCurve().Add(C[slice], commitmentMatrix[share][slice]);
            }
        }

        // store the commitment matrix
        commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitmentMatrix)));

        auto finish = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = finish - start;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::cout << "Commitment generation finished in: " << duration.count() << "s" << std::endl;
        }

        // store the random values used for the Commitments of the own share
        R.resize(numSlices);

        // get the index of the own share by checking the position of the local nodeID in the member list
        for (uint32_t j = 0; j < numSlices; j++)
            R[j] = rValues[nodeIndex_][j];

        // broadcast the commitments
        for (auto &member : DCNetwork_.members()) {
            if (member.second != SELF) {
                OutgoingMessage commitBroadcast(member.second, CommitmentRoundOne, DCNetwork_.nodeID(), commitments);
                DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(commitBroadcast));
            }
        }

        // collect the commitments from the other k-1 members
        while (commitments_.size() < k_) {
            auto commitBroadcast = DCNetwork_.inbox().pop();

            if (commitBroadcast->msgType() == CommitmentRoundOne) {
                // extract and store the commitments
                std::vector<uint8_t> &commitments = commitBroadcast->body();
                size_t numSlices = S.size();
                size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);

                std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
                commitmentMatrix.resize(k_);
                for (auto &share : commitmentMatrix)
                    share.reserve(numSlices);

                // decompress all the points
                for (uint32_t i = 0; i < k_; i++) {
                    for (uint32_t j = 0; j < numSlices; j++) {
                        size_t offset = (i * numSlices + j) * encodedPointSize;
                        CryptoPP::ECPPoint commitment;
                        curve.GetCurve().DecodePoint(commitment, &commitments[offset], encodedPointSize);
                        commitmentMatrix[i].push_back(std::move(commitment));

                        C[j] = curve.GetCurve().Add(C[j], commitment);
                    }
                }
                // Store the decompressed points
                commitments_.insert(std::pair(commitBroadcast->senderID(), std::move(commitmentMatrix)));
            } else {
                DCNetwork_.inbox().push(commitBroadcast);
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
        }
    }

    // distribute the shares to the individual members
    for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
        uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), it);

        if (it->second != SELF) {
            std::vector<uint8_t> rsPairs;

            if (securedRound_) {
                rsPairs.resize(64 * numSlices);
                for (uint32_t slice = 0; slice < numSlices; slice++) {
                    rValues[memberIndex][slice].Encode(&rsPairs[slice * 64], 32);
                    shares[memberIndex][slice].Encode(&rsPairs[slice * 64 + 32], 32);
                }
            } else {
                rsPairs.resize(32 * numSlices);
                for (uint32_t slice = 0; slice < numSlices; slice++) {
                    shares[memberIndex][slice].Encode(&rsPairs[slice * 32], 32);
                }
            }
            OutgoingMessage rsMessage(it->second, RoundOneSharingPartOne, DCNetwork_.nodeID(), rsPairs);
            DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(rsMessage));
        }
    }
}

int RoundOne::sharingPartTwo() {
    size_t numSlices = S.size();
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    for (int remainingShares = 0; remainingShares < k_ - 1; remainingShares++) {
        auto rsMessage = DCNetwork_.inbox().pop();

        if (rsMessage->msgType() == RoundOneSharingPartOne) {
            if (securedRound_) {
                for (int i = 0; i < numSlices; i++) {
                    // extract and decode the random values and the slice of the share
                    CryptoPP::Integer r(&rsMessage->body()[i * 64], 32);
                    CryptoPP::Integer s(&rsMessage->body()[i * 64 + 32], 32);

                    CryptoPP::ECPPoint commitment = commit(r, s);

                    // verify that the commitment is valid
                    if ((commitment.x != commitments_[rsMessage->senderID()][DCNetwork_.nodeID()][i].x)
                        || (commitment.y != commitments_[rsMessage->senderID()][DCNetwork_.nodeID()][i].y)) {

                        // broadcast a blame message which contains the invalid share along with the corresponding r value
                        RoundOne::injectBlameMessage(rsMessage->senderID(), i, r, s);
                        return -1;
                    }

                    R[i] += r;
                    S[i] += s;
                }
            } else {
                for (int i = 0; i < numSlices; i++) {
                    CryptoPP::Integer s;
                    s.Decode(&rsMessage->body()[i * 32], 32);
                    S[i] += s;
                }
            }
        } else {
            DCNetwork_.inbox().push(rsMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    std::vector<uint8_t> rsVector;
    if (securedRound_) {
        rsVector.resize(numSlices * 64);

        for (int i = 0; i < numSlices; i++) {
            R[i] = R[i].Modulo(curve.GetSubgroupOrder());
            R[i].Encode(&rsVector[i * 64], 32);

            S[i] = S[i].Modulo(curve.GetSubgroupOrder());
            S[i].Encode(&rsVector[i * 64 + 32], 32);
        }
    } else {
        rsVector.resize(numSlices * 32);

        for (int i = 0; i < numSlices; i++) {
            S[i] = S[i].Modulo(curve.GetSubgroupOrder());
            S[i].Encode(&rsVector[i * 32], 32);
        }
    }

    for (auto &member : DCNetwork_.members()) {
        if (member.second != SELF) {
            OutgoingMessage rsBroadcast(member.second, RoundOneSharingPartTwo, DCNetwork_.nodeID(), rsVector);
            DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(rsBroadcast));
        }
    }
    return 0;
}

std::vector<uint8_t> RoundOne::resultComputation() {
    size_t numSlices = S.size();
    // collect the added shares from the other k-1 members and validate them by adding the corresponding commitments
    for (int remainingShares = 0; remainingShares < k_ - 1; remainingShares++) {
        auto rsBroadcast = DCNetwork_.inbox().pop();

        if (rsBroadcast->msgType() == RoundOneSharingPartTwo) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                 DCNetwork_.members().find(rsBroadcast->senderID()));

            if (securedRound_) {
                for (int i = 0; i < numSlices; i++) {
                    // extract and decode the random values and the slice of the share
                    CryptoPP::Integer R_(&rsBroadcast->body()[i * 64], 32);
                    CryptoPP::Integer S_(&rsBroadcast->body()[i * 64 + 32], 32);

                    // validate r and s
                    CryptoPP::ECPPoint addedCommitments;
                    for (auto &c : commitments_)
                        addedCommitments = curve.GetCurve().Add(addedCommitments, c.second[memberIndex][i]);

                    CryptoPP::ECPPoint commitment = commit(R_, S_);

                    if ((commitment.x != addedCommitments.x) || (commitment.y != addedCommitments.y)) {
                        // broadcast a blame message which contains the invalid share along with the corresponding r value
                        RoundOne::injectBlameMessage(rsBroadcast->senderID(), i, R_, S_);
                        return std::vector<uint8_t>();
                    }
                    R[i] += R_;
                    S[i] += S_;
                }
            } else {
                for (int i = 0; i < numSlices; i++) {
                    CryptoPP::Integer S_;
                    S_.Decode(&rsBroadcast->body()[i * 32], 32);
                    S[i] += S_;
                }
            }
        } else if (rsBroadcast->msgType() == BlameMessage) {
            RoundOne::handleBlameMessage(rsBroadcast);
            std::cout << "Blame message received" << std::endl;

            return std::vector<uint8_t>();
        } else {
            DCNetwork_.inbox().push(rsBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    // validate the final commitments
    if (securedRound_) {
        for (int i = 0; i < numSlices; i++) {
            R[i] = R[i].Modulo(curve.GetSubgroupOrder());
            S[i] = S[i].Modulo(curve.GetSubgroupOrder());

            CryptoPP::ECPPoint commitment = commit(R[i], S[i]);

            if ((C[i].x != commitment.x) || (C[i].y != commitment.y)) {
                std::cout << "Invalid commitment detected" << std::endl;
                return std::vector<uint8_t>();
            }
        }
    } else {
        for (int i = 0; i < numSlices; i++) {
            S[i] = S[i].Modulo(curve.GetSubgroupOrder());
        }
    }

    // reconstruct the original message
    std::vector<uint8_t> reconstructedMessage;
    reconstructedMessage.resize(msgVector_.size());
    for (int i = 0; i < S.size(); i++) {
        size_t sliceSize = ((msgVector_.size() - 31 * i > 31) ? 31 : msgVector_.size() - 31 * i);
        S[i].Encode(&reconstructedMessage[31 * i], sliceSize);
    }

    RoundOne::printMessageVector(reconstructedMessage);

    return reconstructedMessage;
}

void RoundOne::injectBlameMessage(uint32_t suspectID, uint32_t slice, CryptoPP::Integer &r, CryptoPP::Integer &s) {
    std::vector<uint8_t> messageBody(72);
    // set the suspect's ID
    messageBody[0] = (suspectID & 0xFF000000) >> 24;
    messageBody[1] = (suspectID & 0x00FF0000) >> 16;
    messageBody[2] = (suspectID & 0x0000FF00) >> 8;
    messageBody[3] = (suspectID & 0x000000FF);

    // set the index of the slice
    messageBody[4] = (slice & 0xFF000000) >> 24;
    messageBody[5] = (slice & 0x00FF0000) >> 16;
    messageBody[6] = (slice & 0x0000FF00) >> 8;
    messageBody[7] = (slice & 0x000000FF);

    // store the r and s value
    r.Encode(&messageBody[8], 32);
    s.Encode(&messageBody[40], 32);

    for (auto &member : DCNetwork_.members()) {
        if (member.second != SELF) {
            OutgoingMessage blameMessage(member.second, BlameMessage, DCNetwork_.nodeID(), messageBody);
            DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(blameMessage));
        }
    }
}

void RoundOne::handleBlameMessage(std::shared_ptr<ReceivedMessage>& blameMessage) {
    std::vector<uint8_t>& body = blameMessage->body();
    // check which node is addressed by the blame message
    uint32_t suspectID = (body[0] << 24) | (body[1] << 16) | (body[2] << 8) | body[3];

    // extract the index of the corrupted slice
    uint32_t slice = (body[4] << 24) | (body[5] << 16) | (body[6] << 8) | body[7];

    // extract the random value r and the corrupted slice
    CryptoPP::Integer r(&body[8], 32);
    CryptoPP::Integer s(&body[40], 32);

    // validate that the slice is actually corrupt
    CryptoPP::ECPPoint commitment = commit(r,s);

    uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                         DCNetwork_.members().find(suspectID));

    // compare the commitment, generated using the submitted values, with the commitment
    // which has been broadcasted by the suspect
    if((commitment.x != commitments_[suspectID][memberIndex][slice].x)
        || (commitment.y != commitments_[suspectID][memberIndex][slice].y)) {

        // if the two commitments do not match, the incident is stored
        auto position = DCNetwork_.suspiciousMembers().find(suspectID);

        if(position != DCNetwork_.suspiciousMembers().end()) {
            // if this is the third incident, the node is excluded from the DC Network
            if((position->second) == 2) {
                DCNetwork_.suspiciousMembers().erase(position);
                DCNetwork_.members().erase(suspectID);
            } else {
                position->second++;
            }
        } else {
            DCNetwork_.suspiciousMembers().insert(std::pair(suspectID, 1));
        }
    } else {
        // if the two commitments match, the sender is blamed
        auto position = DCNetwork_.suspiciousMembers().find(blameMessage->senderID());
        if(position != DCNetwork_.suspiciousMembers().end()) {
            // if this is the third incident, the node is excluded from the DC Network
            if((position->second) == 2) {
                DCNetwork_.suspiciousMembers().erase(position);
                DCNetwork_.members().erase(blameMessage->senderID());
            } else {
                position->second++;
            }
        } else {
            DCNetwork_.suspiciousMembers().insert(std::pair(blameMessage->senderID(), 1));
        }
    }
}

inline CryptoPP::ECPPoint RoundOne::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = curve.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, sH);
    return commitment;
}

// helper function to print the slots in the message vector
void RoundOne::printMessageVector(std::vector<uint8_t> &msgVector) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << std::dec << "Node: " << DCNetwork_.nodeID() << std::endl;
    std::cout << "|";
    for (int i = 0; i < 2 * k_; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[4 * i];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[4 * i + 1];
        std::cout << " ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[4 * i + 2];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[4 * i + 3];
        std::cout << "|";
    }
    std::cout << std::endl << std::endl;
}




































