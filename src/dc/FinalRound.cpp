#include <iostream>
#include <cryptopp/oids.h>
#include <thread>
#include <iomanip>
#include "FinalRound.h"
#include "InitState.h"
#include "../datastruct/MessageType.h"
#include "InitialRound.h"
#include "ReadyState.h"

// constructor for a unsecured round
FinalRound::FinalRound(DCNetwork &DCNet, int slotIndex, std::vector<uint16_t> slots)
        : DCNetwork_(DCNet), securedRound_(false), k_(DCNetwork_.k()), slotIndex_(slotIndex),
          slots_(std::move(slots)) {

    curve.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

// constructor for a secured round
FinalRound::FinalRound(DCNetwork& DCNet, int slotIndex, std::vector<uint16_t> slots, std::vector<std::array<uint8_t, 32>> submittedSeeds, std::vector<std::array<uint8_t, 32>> receivedSeeds)
        : DCNetwork_(DCNet), securedRound_(true), k_(DCNetwork_.k()), slotIndex_(slotIndex),
          slots_(std::move(slots)),
          submittedSeeds_(std::move(submittedSeeds)),
          seeds_(std::move(receivedSeeds)), rValues_(k_) {

    curve.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));

    R.resize(slots_.size());
    for (uint32_t slot = 0; slot < slots_.size(); slot++) {
        rValues_[slot].resize(k_);
        DRNG.SetKeyWithIV(seeds_[slot].data(), 16, seeds_[slot].data() + 16, 16);

        size_t numSlices = std::ceil(slots_[slot] / 31.0);
        R[slot].resize(numSlices);
        for (uint32_t share = 0; share < k_; share++) {
            rValues_[slot][share].reserve(numSlices);

            for (uint32_t slice = 0; slice < numSlices; slice++) {
                CryptoPP::Integer r(DRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                rValues_[slot][share].push_back(std::move(r));

                if(share == nodeIndex_)
                    R[slot][slice] = rValues_[slot][nodeIndex_][slice];
            }
        }
    }
}

FinalRound::~FinalRound() {}

std::unique_ptr<DCState> FinalRound::executeTask() {
    size_t numSlots = slots_.size();

    std::vector<size_t> numSlices;
    numSlices.reserve(numSlots);
    // determine the number of slices for each slot individually
    for (uint32_t i = 0; i < numSlots; i++)
        numSlices.push_back(std::ceil(slots_[i] / 31.0));

    std::vector<CryptoPP::Integer> messageSlices;

    if (slotIndex_ > -1) {
        std::vector<uint8_t> submittedMessage = DCNetwork_.submittedMessages().front();
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

    for (uint32_t slot = 0; slot < numSlots; slot++) {
        S[slot].reserve(numSlices[slot]);

        for (uint32_t slice = 0; slice < numSlices[slot]; slice++)
            S[slot].push_back(shares[slot][nodeIndex_][slice]);
    }

    // determine the total number of slices
    size_t totalNumSlices = 0;
    for (auto &slot : shares)
        totalNumSlices += slot[0].size();


    FinalRound::sharingPartOne(totalNumSlices, shares);

    int result = FinalRound::sharingPartTwo(totalNumSlices);
    // a blame message has been received
    if (result < 0) {
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    std::vector<std::vector<uint8_t>> messages = FinalRound::resultComputation();
    if(messages.size() == 0) {
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    // Finally verify that no member has sent a message in the own slot
    if(securedRound_ && (slotIndex_ > -1)) {
        for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), it);

            if(memberIndex != nodeIndex_) {
                size_t numSlices = S[slotIndex_].size();
                // calculate the rValues
                std::vector<std::vector<CryptoPP::Integer>> rValues;
                rValues.reserve(k_);

                DRNG.SetKeyWithIV(submittedSeeds_[memberIndex].data(), 16, submittedSeeds_[memberIndex].data() + 16,16);
                for (uint32_t share = 0; share < k_; share++) {
                    std::vector<CryptoPP::Integer> rValuesShare;
                    rValuesShare.reserve(numSlices);
                    for (uint32_t slice = 0; slice < numSlices; slice++) {
                        CryptoPP::Integer r(DRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                        rValuesShare.push_back(std::move(r));
                    }
                    rValues.push_back(std::move(rValuesShare));
                }

                for (uint32_t slice = 0; slice < numSlices; slice++) {

                    CryptoPP::ECPPoint C_;
                    CryptoPP::Integer R_;
                    for (uint32_t share = 0; share < k_; share++) {
                        C_ = curve.GetCurve().Add(C_, commitments_[memberIndex][slotIndex_][share][slice]);
                        R_ += rValues[share][slice];
                    }
                    R_ = R_.Modulo(curve.GetSubgroupOrder());

                    // create the commitment
                    CryptoPP::Integer S_(CryptoPP::Integer::Zero());
                    CryptoPP::ECPPoint commitment = commit(R_, S_);

                    // validate the commitment
                    if ((C_.x != commitment.x) || (C_.y != commitment.y)) {
                        // TODO undo
                        std::lock_guard<std::mutex> lock(mutex_);
                        std::cout << "Final Commitment invalid" << std::endl;
                    }
                }
            }
        }
    }

    // wait until the next round starts
    std::this_thread::sleep_for(std::chrono::seconds(60));
    return std::make_unique<ReadyState>(DCNetwork_);
}

void FinalRound::sharingPartOne(size_t totalNumSlices, std::vector<std::vector<std::vector<CryptoPP::Integer>>> &shares) {
    size_t numSlots = slots_.size();

    if (securedRound_) {
        C.resize(shares.size());

        size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);
        std::vector<uint8_t> commitmentVector(k_ * totalNumSlices * encodedPointSize);

        std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitments;
        commitments.reserve(numSlots);
        for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
            size_t numSlices = shares[slot][0].size();

            std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
            commitmentMatrix.resize(k_);
            for (auto &share : commitmentMatrix)
                share.reserve(numSlices);

            C[slot].resize(numSlices);

            for (uint32_t share = 0; share < k_; share++) {
                for (uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {

                    // generate the commitment for the j-th slice of the i-th share
                    CryptoPP::ECPPoint commitment = commit(rValues_[slot][share][slice], shares[slot][share][slice]);
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
        for (auto &member : DCNetwork_.members()) {
            if (member.second.connectionID() != SELF) {
                OutgoingMessage commitBroadcast(member.second.connectionID(), CommitmentRoundTwo, DCNetwork_.nodeID(),
                                                commitmentVector);
                DCNetwork_.outbox().push(std::move(commitBroadcast));
            }
        }

        // collect the commitments from the other k-1 members
        while (commitments_.size() < k_) {
            auto commitBroadcast = DCNetwork_.inbox().pop();

            if (commitBroadcast.msgType() == CommitmentRoundTwo) {
                size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);

                std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitments;
                commitments.reserve(numSlots);

                // decompress all the points
                for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                    size_t numSlices = shares[slot][0].size();

                    std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix(k_);
                    for (auto &share : commitmentMatrix)
                        share.reserve(numSlices);

                    for (uint32_t share = 0; share < k_; share++) {
                        for (uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {
                            CryptoPP::ECPPoint commitment;
                            curve.GetCurve().DecodePoint(commitment, &commitBroadcast.body()[offset],
                                                         encodedPointSize);

                            C[slot][slice] = curve.GetCurve().Add(C[slot][slice], commitment);
                            commitmentMatrix[share].push_back(std::move(commitment));
                        }
                    }
                    commitments.push_back(std::move(commitmentMatrix));
                }
                // Store the decompressed points
                commitments_.insert(std::pair(commitBroadcast.senderID(), std::move(commitments)));
            } else {
                DCNetwork_.inbox().push(commitBroadcast);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
    }

    // distribute the shares to the individual members
    for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
        uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), it);

        if (it->second.connectionID() != SELF) {
            std::vector<uint8_t> sharingMessage;
            if (securedRound_)
                sharingMessage.resize(64 * totalNumSlices);
            else
                sharingMessage.resize(32 * totalNumSlices);

            for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                size_t numSlices = shares[slot][memberIndex].size();

                for (uint32_t slice = 0; slice < numSlices; slice++) {
                    if (securedRound_) {
                        rValues_[slot][memberIndex][slice].Encode(&sharingMessage[offset], 32);
                        shares[slot][memberIndex][slice].Encode(&sharingMessage[offset + 32], 32);
                        offset += 64;
                    } else {
                        shares[slot][memberIndex][slice].Encode(&sharingMessage[offset], 32);
                        offset += 32;
                    }
                }
            }

            OutgoingMessage rsMessage(it->second.connectionID(), RoundTwoSharingPartOne, DCNetwork_.nodeID(),
                                      sharingMessage);
            DCNetwork_.outbox().push(std::move(rsMessage));
        }
    }
}

int FinalRound::sharingPartTwo(size_t totalNumSlices) {
    size_t numSlots = slots_.size();

    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = k_-1;
    while(remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == RoundTwoSharingPartOne) {
            for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                size_t numSlices = S[slot].size();

                for (uint32_t slice = 0; slice < numSlices; slice++) {
                    if (securedRound_) {
                        CryptoPP::Integer r(&sharingMessage.body()[offset], 32);
                        CryptoPP::Integer s(&sharingMessage.body()[offset + 32], 32);
                        offset += 64;

                        // verify that the corresponding commitment is valid
                        CryptoPP::ECPPoint commitment = commit(r, s);
                        // if the commitment is invalid, blame the sender
                        if ((commitment.x != commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].x)
                            || (commitment.y != commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].y)) {

                            // TODO undo
                            //FinalRound::injectBlameMessage(sharingMessage.senderID(), slot, slice, s);
                            std::lock_guard<std::mutex> lock(mutex_);
                            std::cout << "Invalid commitment detected 1" << std::endl;
                            //return -1;
                        }
                        R[slot][slice] += r;
                        S[slot][slice] += s;
                    } else {
                        CryptoPP::Integer s(&sharingMessage.body()[offset], 32);
                        S[slot][slice] += s;
                        offset += 32;
                    }
                }

            }
            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // construct the sharing broadcast which includes the added shares
    std::vector<uint8_t> sharingBroadcast;
    if(securedRound_)
        sharingBroadcast.resize(64 * totalNumSlices);
    else
        sharingBroadcast.resize(32 * totalNumSlices);

    for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
        for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
            S[slot][slice] = S[slot][slice].Modulo(curve.GetSubgroupOrder());

            if(securedRound_) {
                R[slot][slice] = R[slot][slice].Modulo(curve.GetSubgroupOrder());
                R[slot][slice].Encode(&sharingBroadcast[offset],32);
                S[slot][slice].Encode(&sharingBroadcast[offset] + 32,32);
                offset += 64;
            } else {
                S[slot][slice].Encode(&sharingBroadcast[offset],32);
                offset += 32;
            }
        }
    }

    // Broadcast the added shares in the DC network
    for (auto &member : DCNetwork_.members()) {
        if (member.second.connectionID() != SELF) {
            OutgoingMessage rsBroadcast(member.second.connectionID(), RoundTwoSharingPartTwo, DCNetwork_.nodeID(),
                                        sharingBroadcast);
            DCNetwork_.outbox().push(std::move(rsBroadcast));
        }
    }
    return 0;
}

std::vector<std::vector<uint8_t>> FinalRound::resultComputation() {
    size_t numSlots = S.size();

    uint32_t remainingShares = k_-1;
    while(remainingShares > 0) {
        auto sharingBroadcast = DCNetwork_.inbox().pop();

        if (sharingBroadcast.msgType() == RoundTwoSharingPartTwo) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                 DCNetwork_.members().find(sharingBroadcast.senderID()));

            for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                for (uint32_t slice = 0; slice < S[slot].size(); slice++) {

                    CryptoPP::Integer S_;
                    if(securedRound_) {
                        CryptoPP::Integer R_(&sharingBroadcast.body()[offset], 32);
                        S_.Decode(&sharingBroadcast.body()[offset + 32], 32);
                        offset += 64;

                        R[slot][slice] += R_;

                        CryptoPP::ECPPoint C_;
                        for (auto &c : commitments_)
                            C_ = curve.GetCurve().Add(C_, c.second[slot][memberIndex][slice]);

                        CryptoPP::ECPPoint commitment = commit(R_, S_);

                        // if the commitment is invalid, blame the sender
                        if ((commitment.x != C_.x) || (commitment.y != C_.y)) {
                            // TODO undo
                            std::cout << "Invalid commitment detected" << std::endl;
                            //FinalRound::injectBlameMessage(sharingBroadcast.senderID(), slot, slice, S_);

                            //return std::vector<std::vector<uint8_t>>();
                        }
                    } else {
                        S_.Decode(&sharingBroadcast.body()[offset], 32);
                        offset += 32;
                    }
                    S[slot][slice] += S_;
                }
            }
            remainingShares--;
        } else if (sharingBroadcast.msgType() == BlameMessage) {
            //FinalRound::handleBlameMessage(sharingBroadcast);
            return std::vector<std::vector<uint8_t>>();
        } else {
            DCNetwork_.inbox().push(sharingBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // final commitment validation
    if (securedRound_) {
        for (uint32_t slot = 0; slot < numSlots; slot++) {
            for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
                S[slot][slice] = S[slot][slice].Modulo(curve.GetSubgroupOrder());

                CryptoPP::ECPPoint commitment = commit(R[slot][slice], S[slot][slice]);

                if ((C[slot][slice].x != commitment.x) || (C[slot][slice].y != commitment.y)) {
                    // TODO undo
                    std::cout << "Invalid commitment detected" << std::endl;
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
        std::cout << "Node: " << std::dec << DCNetwork_.nodeID() << std::endl;
        for (auto &slot : reconstructedMessageSlots) {
            std::cout << "|";
            for (uint8_t c : slot) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
            }
            std::cout << "|" << std::endl;
        }
        std::cout << std::endl;
    }
    return reconstructedMessageSlots;
}

inline CryptoPP::ECPPoint FinalRound::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = curve.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, sH);
    return commitment;
}

void FinalRound::injectBlameMessage(uint32_t suspectID, uint32_t slot, uint32_t slice, CryptoPP::Integer &s) {
    std::vector<uint8_t> messageBody(44);
    // set the suspect's ID
    messageBody[0] = (suspectID & 0xFF000000) >> 24;
    messageBody[1] = (suspectID & 0x00FF0000) >> 16;
    messageBody[2] = (suspectID & 0x0000FF00) >> 8;
    messageBody[3] = (suspectID & 0x000000FF);

    // set the index of the slot
    messageBody[4] = (slot & 0xFF000000) >> 24;
    messageBody[5] = (slot & 0x00FF0000) >> 16;
    messageBody[6] = (slot & 0x0000FF00) >> 8;
    messageBody[7] = (slot & 0x000000FF);

    // set the index of the slice
    messageBody[6] = (slice & 0xFF000000) >> 24;
    messageBody[9] = (slice & 0x00FF0000) >> 16;
    messageBody[10] = (slice & 0x0000FF00) >> 8;
    messageBody[11] = (slice & 0x000000FF);

    // store the corrupt share
    s.Encode(&messageBody[12], 32);

    for (auto &member : DCNetwork_.members()) {
        if (member.second.connectionID() != SELF) {
            OutgoingMessage blameMessage(member.second.connectionID(), BlameMessage, DCNetwork_.nodeID(), messageBody);
            DCNetwork_.outbox().push(blameMessage);
        }
    }
}

/*
void FinalRound::handleBlameMessage(std::shared_ptr<ReceivedMessage>& blameMessage) {
    std::vector<uint8_t>& body = blameMessage->body();
    // check which node is addressed by the blame message
    uint32_t suspectID = (body[0] << 24) | (body[1] << 16) | (body[2] << 8) | body[3];

    // extract the index of the slot
    uint32_t slot = (body[4] << 24) | (body[5] << 16) | (body[6] << 8) | body[7];

    // extract the index of the corrupted slice
    uint32_t slice = (body[8] << 24) | (body[9] << 16) | (body[10] << 8) | body[11];

    // extract the the corrupted slice
    CryptoPP::Integer s(&body[12], 32);

    // validate that the slice is actually corrupt
    CryptoPP::ECPPoint commitment = commit(rValues_[suspectID][slot][blameMessage->senderID()][slice], s);

    uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                         DCNetwork_.members().find(suspectID));

    // compare the commitment, generated using the submitted values, with the commitment
    // which has been broadcasted by the suspect
    if((commitment.x != commitments_[suspectID][slot][memberIndex][slice].x)
       || (commitment.y != commitments_[suspectID][slot][memberIndex][slice].y)) {

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
*/












