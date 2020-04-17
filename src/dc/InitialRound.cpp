#include <iostream>
#include <thread>
#include <cryptopp/oids.h>
#include <iomanip>
#include "InitialRound.h"
#include "InitState.h"
#include "FinalRound.h"
#include "../datastruct/MessageType.h"
#include "ReadyState.h"
#include "SeedRound.h"

std::mutex mutex_;

InitialRound::InitialRound(DCNetwork &DCNet)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()) {
    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

InitialRound::~InitialRound() {}

std::unique_ptr<DCState> InitialRound::executeTask() {
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
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    size_t slotSize = 8 + 33 * k_;
    size_t numSlices = std::ceil(slotSize / 31.0);

    std::vector<CryptoPP::Integer> messageSlices;

    int slotIndex = -1;
    if (l > 0) {
        std::vector<uint8_t> messageSlot(slotSize);
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        slotIndex = PRNG.GenerateWord32(0, 2 * k_ - 1);

        // set the values in Big Endian format
        messageSlot[4] = static_cast<uint8_t>((r & 0xFF00) >> 8);
        messageSlot[5] = static_cast<uint8_t>((r & 0x00FF));
        messageSlot[6] = static_cast<uint8_t>((l & 0xFF00) >> 8);
        messageSlot[7] = static_cast<uint8_t>((l & 0x00FF));

        // generate k random seeds, required for the commitments in the second round
        submittedSeeds_.reserve(k_);

        for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), it);

            std::array<uint8_t, 32> seed;

            // generate an ephemeral EC key pair
            CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            CryptoPP::ECPPoint rG = curve_.ExponentiateBase(r);

            // Perform an ephemeral ECDH KE with the given public key
            CryptoPP::Integer sharedSecret = curve_.GetCurve().ScalarMultiply(it->second.publicKey(), r).x;

            sharedSecret.Encode(seed.data(), 32);

            curve_.GetCurve().EncodePoint(&messageSlot[8 + 33 * memberIndex], rG, true);

            // store the seed
            submittedSeeds_.push_back(std::move(seed));
        }

        // Calculate the CRC
        CRC32_.Update(&messageSlot[4], 4 + 33 * k_);
        CRC32_.Final(messageSlot.data());

        // subdivide the message into slices
        messageSlices.reserve(numSlices);
        for (uint32_t i = 0; i < numSlices; i++) {
            size_t sliceSize = ((slotSize - 31 * i > 31) ? 31 : slotSize - 31 * i);
            CryptoPP::Integer slice(&messageSlot[31 * i], sliceSize);
            messageSlices.push_back(std::move(slice));
        }

    }

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> shares(2 * k_);
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        shares[slot].resize(k_);

        // initialize the slices of the k-th share with zeroes
        // except the slices of the own message slot
        if (slotIndex == slot) {
            for (uint32_t slice = 0; slice < numSlices; slice++)
                shares[slot][k_ - 1].push_back(messageSlices[slice]);
        } else {
            for (uint32_t slice = 0; slice < numSlices; slice++)
                shares[slot][k_ - 1].push_back(CryptoPP::Integer::Zero());
        }

        // fill the first slices of the first k-1 shares with random values
        // and subtract the values from the corresponding slices in the k-th share
        for (uint32_t share = 0; share < k_ - 1; share++) {
            shares[slot][share].reserve(numSlices);

            for (uint32_t slice = 0; slice < numSlices; slice++) {
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
                // subtract the value from the corresponding slice in the k-th share
                shares[slot][k_ - 1][slice] -= r;
                // store the random value in the slice of this share
                shares[slot][share].push_back(std::move(r));
            }
        }

        // reduce the slices in the k-th share
        for (uint32_t slice = 0; slice < numSlices; slice++)
            shares[slot][k_ - 1][slice] = shares[slot][k_ - 1][slice].Modulo(curve_.GetSubgroupOrder());
    }

    // store the slices of the own share in S
    S.resize(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        S[slot].reserve(numSlices);
        for (uint32_t slice = 0; slice < numSlices; slice++) {
            S[slot].push_back(shares[slot][nodeIndex_][slice]);
        }
    }

    // generate and broadcast the commitments for the first round
    InitialRound::sharingPartOne(shares);

    // collect and validate the shares
    int result = InitialRound::sharingPartTwo();
    // a blame message has been received
    if (result < 0) {
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    // collect and validate the final shares
    std::vector<std::vector<uint8_t>> finalMessageVector = InitialRound::resultComputation();
    // Check if the protocol's execution has been interrupted by a blame message
    if (finalMessageVector.size() == 0) {
        // a blame message indicates that a member may have been excluded from the group
        // therefore a transition to the init state is performed,
        // which will execute a group membership protocol
        // TODO clean up the inbox
        std::this_thread::sleep_for(std::chrono::seconds(60));
        return std::make_unique<InitState>(DCNetwork_);
    }

    // prepare round two
    std::vector<uint16_t> slots;
    std::vector<std::array<uint8_t, 32>> receivedSeeds;

    // determine the non-empty slots in the message vector
    // and calculate the index of the own slot if present
    int finalSlotIndex = -1;
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        if (slotIndex == slot)
            finalSlotIndex = slots.size();

        uint16_t slotSize = (finalMessageVector[slot][6] << 8) | finalMessageVector[slot][7];
        if (slotSize > 0) {
            // verify the CRC
            CRC32_.Update(&finalMessageVector[slot][4], 4 + 33 * k_);

            bool valid = CRC32_.Verify(finalMessageVector[slot].data());

            if (!valid) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    std::cout << "Invalid CRC detected." << std::endl;
                    std::cout << "Restarting Round One." << std::endl;
                }
                return std::make_unique<InitialRound>(DCNetwork_);
            }

            //decrypt and extract the own seed for the each slot
            CryptoPP::ECPPoint rG;
            curve_.GetCurve().DecodePoint(rG, &finalMessageVector[slot][8 + 33 * nodeIndex_], 33);

            // Perform an ephemeral ECDH KE with the given public key
            CryptoPP::Integer sharedSecret = curve_.GetCurve().ScalarMultiply(rG, DCNetwork_.privateKey()).x;

            std::array<uint8_t, 32> seed;
            sharedSecret.Encode(seed.data(), 32);

            receivedSeeds.push_back(std::move(seed));


            // store the size of the slot along with the seed
            slots.push_back(slotSize);
        }
    }

    // if no member wants to send a message, return to the Ready state
    if (slots.size() == 0) {
        return std::make_unique<ReadyState>(DCNetwork_);
    } else {
        return std::make_unique<FinalRound>(DCNetwork_, finalSlotIndex, std::move(slots),
                                            std::move(submittedSeeds_),
                                            std::move(receivedSeeds));
    }
}

void InitialRound::sharingPartOne(std::vector<std::vector<std::vector<CryptoPP::Integer>>> &shares) {
    size_t numSlices = std::ceil((8 + 33 * k_) / 31.0);

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues(2 * k_);
    // init C
    C.resize(2 * k_);
    R.resize(2 * k_);

    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);
    std::vector<std::vector<uint8_t>> encodedCommitments(2 * k_);
    std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        rValues[slot].resize(k_);
        R[slot].reserve(numSlices);
        C[slot].resize(numSlices);
        commitmentCube[slot].resize(k_);
        encodedCommitments[slot].resize(2 + k_ * numSlices * encodedPointSize);
        for (uint32_t share = 0, offset = 2; share < k_; share++) {
            rValues[slot][share].reserve(numSlices);
            commitmentCube[slot][share].reserve(numSlices);

            // encode the current slot in the first two bytes
            encodedCommitments[slot][0] = (slot & 0xFF00) >> 8;
            encodedCommitments[slot][1] = slot & 0x00FF;
            for (uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {
                // generate the random value r for this slice of the share
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
                rValues[slot][share].push_back(std::move(r));

                // generate the commitment for the j-th slice of the i-th share
                CryptoPP::ECPPoint commitment = commit(rValues[slot][share][slice], shares[slot][share][slice]);

                // store the commitment
                commitmentCube[slot][share].push_back(std::move(commitment));

                // compress the commitment and store in the given position in the vector
                curve_.GetCurve().EncodePoint(&encodedCommitments[slot][offset], commitmentCube[slot][share][slice],
                                              true);

                // Add the commitment to the sum C
                C[slot][slice] = curve_.GetCurve().Add(C[slot][slice], commitmentCube[slot][share][slice]);
            }
        }
    }

    // store the commitment matrix
    commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitmentCube)));

    // store the random values used for the Commitments of the own share

    // get the index of the own share by checking the position of the local nodeID in the member list
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        for (uint32_t slice = 0; slice < numSlices; slice++) {
            R[slot].push_back(rValues[slot][nodeIndex_][slice]);
        }
    }

    // broadcast the commitments
    // ensure that the messages arrive evenly distributed in time
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2 * k_; slot++) {
            OutgoingMessage commitBroadcast(position->second.connectionID(), CommitmentRoundOne,
                                            DCNetwork_.nodeID(), encodedCommitments[slot]);
            DCNetwork_.outbox().push(std::move(commitBroadcast));
        }
    }

    // prepare the commitment storage
    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube;
        commitmentCube.reserve(2 * k_);

        commitments_.insert(std::pair(member->second.nodeID(), std::move(commitmentCube)));
    }

    // collect the commitments from the other k-1 members
    uint32_t remainingCommitments = 2 * k_ * (k_ - 1);
    while (remainingCommitments > 0) {
        auto commitBroadcast = DCNetwork_.inbox().pop();

        if (commitBroadcast.msgType() == CommitmentRoundOne) {

            std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
            commitmentMatrix.reserve(k_);

            // decode the slot and the share
            uint32_t slot = (commitBroadcast.body()[0] << 8) | (commitBroadcast.body()[1]);

            for (uint32_t share = 0, offset = 2; share < k_; share++) {
                std::vector<CryptoPP::ECPPoint> commitmentVector;
                commitmentVector.reserve(numSlices);

                for (uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {
                    CryptoPP::ECPPoint commitment;
                    curve_.GetCurve().DecodePoint(commitment, &commitBroadcast.body()[offset],
                                                  encodedPointSize);

                    C[slot][slice] = curve_.GetCurve().Add(C[slot][slice], commitment);
                    commitmentVector.push_back(std::move(commitment));
                }
                commitmentMatrix.push_back(std::move(commitmentVector));
            }
            commitments_[commitBroadcast.senderID()].push_back(std::move(commitmentMatrix));

            remainingCommitments--;
        } else {
            DCNetwork_.inbox().push(commitBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), position);
        for (uint32_t slot = 0; slot < 2 * k_; slot++) {

            std::vector<uint8_t> sharingMessage(2 + 64 * numSlices);
            sharingMessage[0] = (slot & 0xFF00) >> 8;
            sharingMessage[1] = (slot & 0x00FF);
            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
                rValues[slot][memberIndex][slice].Encode(&sharingMessage[offset], 32);
                shares[slot][memberIndex][slice].Encode(&sharingMessage[offset + 32], 32);
            }

            OutgoingMessage rsMessage(position->second.connectionID(), RoundOneSharingPartOne, DCNetwork_.nodeID(),
                                      sharingMessage);
            DCNetwork_.outbox().push(std::move(rsMessage));
        }
    }
}

int InitialRound::sharingPartTwo() {
    size_t numSlices = std::ceil((8 + 33 * k_) / 31.0);
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = 2 * k_ * (k_ - 1);
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == RoundOneSharingPartOne) {

            uint32_t slot = (sharingMessage.body()[0] << 8) | sharingMessage.body()[1];

            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
                CryptoPP::Integer r(&sharingMessage.body()[offset], 32);
                CryptoPP::Integer s(&sharingMessage.body()[offset + 32], 32);

                // verify that the corresponding commitment is valid
                CryptoPP::ECPPoint commitment = commit(r, s);
                // if the commitment is invalid, blame the sender
                if ((commitment.x != commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].x)
                    || (commitment.y != commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].y)) {
                    //SeedRound::injectBlameMessage(sharingMessage.senderID(), slot, slice, s);
                    std::lock_guard<std::mutex> lock(mutex_);
                    std::cout << "Invalid commitment detected 1" << std::endl;
                    return -1;
                }
                R[slot][slice] += r;
                S[slot][slice] += s;
            }

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // construct the sharing broadcast which includes the added shares
    std::vector<std::vector<uint8_t>> sharingBroadcast;
    sharingBroadcast.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<uint8_t> broadcastSlot(2 + 64 * numSlices);
        broadcastSlot[0] = (slot & 0xFF00) >> 8;
        broadcastSlot[1] = (slot & 0x00FF);

        for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
            S[slot][slice] = S[slot][slice].Modulo(curve_.GetSubgroupOrder());
            R[slot][slice] = R[slot][slice].Modulo(curve_.GetSubgroupOrder());

            R[slot][slice].Encode(&broadcastSlot[offset], 32);
            S[slot][slice].Encode(&broadcastSlot[offset] + 32, 32);
        }

        sharingBroadcast.push_back(std::move(broadcastSlot));
    }

    // broadcast the added shares
    // ensure that the messages arrive evenly distributed in time
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2 * k_; slot++) {
            OutgoingMessage rsBroadcast(position->second.connectionID(), RoundOneSharingPartTwo, DCNetwork_.nodeID(),
                                        sharingBroadcast[slot]);
            DCNetwork_.outbox().push(std::move(rsBroadcast));
        }
    }

    return 0;
}

std::vector<std::vector<uint8_t>> InitialRound::resultComputation() {
    size_t numSlices = std::ceil((8 + 33 * k_) / 31.0);
    // collect the added shares from the other k-1 members and validate them by adding the corresponding commitments
    uint32_t remainingShares = 2 * k_ * (k_ - 1);
    while (remainingShares > 0) {
        auto rsBroadcast = DCNetwork_.inbox().pop();

        if (rsBroadcast.msgType() == RoundOneSharingPartTwo) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                 DCNetwork_.members().find(rsBroadcast.senderID()));


            uint32_t slot = (rsBroadcast.body()[0] << 8) | rsBroadcast.body()[1];
            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
                // extract and decode the random values and the slice of the share
                CryptoPP::Integer R_(&rsBroadcast.body()[offset], 32);
                CryptoPP::Integer S_(&rsBroadcast.body()[offset + 32], 32);
                // validate r and s
                CryptoPP::ECPPoint addedCommitments;
                for (auto &c : commitments_)
                    addedCommitments = curve_.GetCurve().Add(addedCommitments,
                                                             c.second[slot][memberIndex][slice]);

                CryptoPP::ECPPoint commitment = commit(R_, S_);

                if ((commitment.x != addedCommitments.x) || (commitment.y != addedCommitments.y)) {
                    // broadcast a blame message which contains the invalid share along with the corresponding r values
                    std::cout << "Invalid commitment detected" << std::endl;
                    InitialRound::injectBlameMessage(rsBroadcast.senderID(), slice, R_, S_);
                    return std::vector<std::vector<uint8_t>>();
                }
                R[slot][slice] += R_;
                S[slot][slice] += S_;
            }

            remainingShares--;
        } else if (rsBroadcast.msgType() == BlameMessage) {
            //InitialRound::handleBlameMessage(rsBroadcast);
            std::cout << "Blame message received" << std::endl;

            return std::vector<std::vector<uint8_t>>();
        } else {
            DCNetwork_.inbox().push(rsBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // validate the final commitments
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        for (uint32_t slice = 0; slice < numSlices; slice++) {
            R[slot][slice] = R[slot][slice].Modulo(curve_.GetSubgroupOrder());
            S[slot][slice] = S[slot][slice].Modulo(curve_.GetSubgroupOrder());

            CryptoPP::ECPPoint commitment = commit(R[slot][slice], S[slot][slice]);

            if ((C[slot][slice].x != commitment.x) || (C[slot][slice].y != commitment.y)) {
                std::lock_guard<std::mutex> lock(mutex_);
                std::cout << "Final commitment invalid" << std::endl;

                return std::vector<std::vector<uint8_t>>();
            }
        }
    }

    // reconstruct the original message
    std::vector<std::vector<uint8_t>> finalMessageSlots;
    finalMessageSlots.resize(2 * k_);
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        finalMessageSlots[slot].resize(8 + 33 * k_);
        for (uint32_t slice = 0; slice < numSlices; slice++) {
            size_t sliceSize = (((8 + 33 * k_) - 31 * slice > 31) ? 31 : (8 + 33 * k_) - 31 * slice);
            S[slot][slice].Encode(&finalMessageSlots[slot][31 * slice], sliceSize);
        }
    }

    InitialRound::printSlots(finalMessageSlots);

    return finalMessageSlots;
}

void InitialRound::injectBlameMessage(uint32_t suspectID, uint32_t slice, CryptoPP::Integer &r, CryptoPP::Integer &s) {
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
        if (member.second.connectionID() != SELF) {
            OutgoingMessage blameMessage(member.second.connectionID(), BlameMessage, DCNetwork_.nodeID(), messageBody);
            DCNetwork_.outbox().push(std::move(blameMessage));
        }
    }
}

/*
void InitialRound::handleBlameMessage(std::shared_ptr<ReceivedMessage>& blameMessage) {
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
*/

inline CryptoPP::ECPPoint InitialRound::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve_.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = curve_.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = curve_.GetCurve().Add(rG, sH);
    return commitment;
}

// helper function to print the slots in the message vector
void InitialRound::printSlots(std::vector<std::vector<uint8_t>> &slots) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << std::dec << "Node: " << DCNetwork_.nodeID() << std::endl;
    std::cout << "| ";
    for (int slot = 0; slot < 2 * k_; slot++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot][0];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot][1];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot][2];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot][3];
        std::cout << " ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot][4];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot][5];
        std::cout << " ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot][6];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot][7];
        std::cout << " | ";
    }
    std::cout << std::endl << std::endl;
}




































