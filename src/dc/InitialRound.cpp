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

InitialRound::InitialRound(DCNetwork &DCNet, ProtocolMode protocolMode)
        : DCNetwork_(DCNet), protocolMode_(protocolMode), k_(DCNetwork_.k()) {
    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));

    if (protocolMode_ == Paper)
        msgVector_.resize(2 * k_ * (8 + 33 * k_));
    else
        msgVector_.resize(2 * k_ * 8);
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

    int p = -1;
    if (l > 0) {
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        p = PRNG.GenerateWord32(0, 2 * k_ - 1);

        // set the values in Big Endian format
        msgVector_[8 * p + 4] = static_cast<uint8_t>((r & 0xFF00) >> 8);
        msgVector_[8 * p + 5] = static_cast<uint8_t>((r & 0x00FF));
        msgVector_[8 * p + 6] = static_cast<uint8_t>((l & 0xFF00) >> 8);
        msgVector_[8 * p + 7] = static_cast<uint8_t>((l & 0x00FF));

        // generate k random seeds, required for the commitments in the second round
        if(protocolMode_ == Paper) {
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

                curve_.GetCurve().EncodePoint(&msgVector_[16 * k_ + p * 33 * k_ + 33 * memberIndex], rG, true);

                // store the seed
                submittedSeeds_.push_back(std::move(seed));
            }
        }

        // Calculate the CRC
        CRC32_.Update(&msgVector_[8 * p + 4], 4);
        if (protocolMode_ == Paper)
            CRC32_.Update(&msgVector_[16 * k_ + p * 33 * k_], 33 * k_);

        CRC32_.Final(&msgVector_[8 * p]);
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

    InitialRound::printMessageVector(msgVector_);

    // Split each slice into k shares
    std::vector<std::vector<CryptoPP::Integer>> shares;
    shares.resize(k_);

    // initialize the slices of the k-th share with zeroes
    shares[k_ - 1].resize(numSlices);

    // fill the first k-1 set of shares with random data
    for (uint32_t i = 0; i < k_ - 1; i++) {
        shares[i].reserve(numSlices);
        for (uint32_t j = 0; j < numSlices; j++) {
            CryptoPP::Integer slice(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            shares[k_ - 1][j] -= slice;
            shares[i].push_back(std::move(slice));
        }
    }

    // calculate the k-th share
    for (uint32_t j = 0; j < numSlices; j++) {
        shares[k_ - 1][j] += msgSlices[j];
        shares[k_ - 1][j] = shares[k_ - 1][j].Modulo(curve_.GetSubgroupOrder());
    }

    // store the slices of the own share in S
    S.resize(numSlices);

    for (uint32_t j = 0; j < numSlices; j++)
        S[j] = shares[nodeIndex_][j];

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
    std::vector<uint8_t> finalMessageVector = InitialRound::resultComputation();
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
    int slotIndex = -1;
    for (uint32_t i = 0; i < 2 * k_; i++) {
        if (p == i)
            slotIndex = slots.size();
        uint16_t slotSize = (finalMessageVector[8 * i + 6] << 8) | finalMessageVector[8 * i + 7];
        if (slotSize > 0) {
            // verify the CRC
            CRC32_.Update(&finalMessageVector[8 * i + 4], 4);

            if (protocolMode_ == Paper)
                CRC32_.Update(&finalMessageVector[16 * k_ + 33 * k_ * i], 33 * k_);

            bool valid = CRC32_.Verify(&finalMessageVector[8 * i]);

            if (!valid) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    std::cout << "Invalid CRC detected." << std::endl;
                    std::cout << "Restarting Round One." << std::endl;
                }
                return std::make_unique<InitialRound>(DCNetwork_, protocolMode_);
            }

            if (protocolMode_ == Paper) {
                //decrypt and extract the own seed for the each slot
                CryptoPP::ECPPoint rG;
                curve_.GetCurve().DecodePoint(rG, &finalMessageVector[16 * k_ + 33 * k_ * i + 33 * nodeIndex_], 33);

                // Perform an ephemeral ECDH KE with the given public key
                CryptoPP::Integer sharedSecret = curve_.GetCurve().ScalarMultiply(rG, DCNetwork_.privateKey()).x;

                std::array<uint8_t, 32> seed;
                sharedSecret.Encode(seed.data(), 32);

                receivedSeeds.push_back(std::move(seed));
            }

            // store the size of the slot along with the seed
            slots.push_back(slotSize);
        }
    }

    // if no member wants to send a message, return to the Ready state
    if (slots.size() == 0) {
        return std::make_unique<ReadyState>(DCNetwork_);
    } else {
        if(protocolMode_ == Paper)
            return std::make_unique<FinalRound>(DCNetwork_, slotIndex, std::move(slots), std::move(submittedSeeds_),
                                                std::move(receivedSeeds));
        else if(protocolMode_ == Experimental)
            return std::make_unique<SeedRound>(DCNetwork_, slotIndex, std::move(slots));
        else
            return std::make_unique<FinalRound>(DCNetwork_, slotIndex, std::move(slots));
    }
}

void InitialRound::sharingPartOne(std::vector<std::vector<CryptoPP::Integer>> &shares) {
    size_t numSlices = shares[0].size();
    std::vector<std::vector<CryptoPP::Integer>> rValues;
    if(!(protocolMode_ == Unsecured)) {
        size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

        std::vector<std::vector<uint8_t>> encodedCommitments;
        encodedCommitments.reserve(k_);

        rValues.resize(k_);
        for (auto& share : rValues)
            share.reserve(numSlices);

        // init C
        C.resize(numSlices);

        std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
        commitmentMatrix.resize(k_);
        for (auto &share : commitmentMatrix)
            share.reserve(numSlices);

        for (uint32_t share = 0; share < k_; share++) {

            std::vector<uint8_t> commitmentVector(numSlices * encodedPointSize);
            for (uint32_t slice = 0; slice < numSlices; slice++) {
                // generate the random value r for this slice of the share
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
                rValues[share].push_back(std::move(r));

                // generate the commitment for the j-th slice of the i-th share
                CryptoPP::ECPPoint commitment = commit(rValues[share][slice], shares[share][slice]);

                // store the commitment
                commitmentMatrix[share].push_back(std::move(commitment));

                // compress the commitment and store in the given position in the vector
                size_t offset = slice * encodedPointSize;
                curve_.GetCurve().EncodePoint(&commitmentVector[offset], commitmentMatrix[share][slice], true);

                // Add the commitment to the sum C
                C[slice] = curve_.GetCurve().Add(C[slice], commitmentMatrix[share][slice]);
            }
            encodedCommitments.push_back(std::move(commitmentVector));
        }

        // store the commitment matrix
        commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitmentMatrix)));

        // store the random values used for the Commitments of the own share
        R.resize(numSlices);

        // get the index of the own share by checking the position of the local nodeID in the member list
        for (uint32_t j = 0; j < numSlices; j++)
            R[j] = rValues[nodeIndex_][j];

        // broadcast the commitments
        for (auto &member : DCNetwork_.members()) {
            if (member.second.connectionID() != SELF) {
                for (uint32_t share = 0; share < k_; share++) {
                    OutgoingMessage commitBroadcast(member.second.connectionID(), CommitmentRoundOne,
                                                    DCNetwork_.nodeID(), encodedCommitments[share]);
                    DCNetwork_.outbox().push(std::move(commitBroadcast));
                }
            }
        }

        // prepare the commitment storage
        for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
            std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
            commitmentMatrix.reserve(k_);
            commitments_.insert(std::pair(member->second.nodeID(), std::move(commitmentMatrix)));
        }

        // collect the commitments from the other k-1 members
        uint32_t remainingCommitments = k_ * (k_ - 1);
        while (remainingCommitments > 0) {
            auto commitBroadcast = DCNetwork_.inbox().pop();

            if (commitBroadcast.msgType() == CommitmentRoundOne) {
                // extract and store the commitments
                std::vector<uint8_t> &commitments = commitBroadcast.body();
                size_t numSlices = S.size();
                size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

                std::vector<CryptoPP::ECPPoint> commitmentVector;
                commitmentVector.reserve(numSlices);

                // decompress all the points
                for(uint32_t slice = 0; slice < numSlices; slice++) {
                    size_t offset = slice * encodedPointSize;
                    CryptoPP::ECPPoint commitment;
                    curve_.GetCurve().DecodePoint(commitment, &commitments[offset], encodedPointSize);
                    commitmentVector.push_back(std::move(commitment));

                    C[slice] = curve_.GetCurve().Add(C[slice], commitment);
                }
                // Store the decompressed points
                commitments_[commitBroadcast.senderID()].push_back(commitmentVector);
                //commitments_.insert(std::pair(commitBroadcast.senderID(), std::move(commitmentMatrix)));
                remainingCommitments--;
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
            std::vector<uint8_t> rsPairs;

            if(!(protocolMode_ == Unsecured)) {
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
            OutgoingMessage rsMessage(it->second.connectionID(), RoundOneSharingPartOne, DCNetwork_.nodeID(), rsPairs);
            DCNetwork_.outbox().push(std::move(rsMessage));
        }
    }
}

int InitialRound::sharingPartTwo() {
    size_t numSlices = S.size();
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto rsMessage = DCNetwork_.inbox().pop();

        if (rsMessage.msgType() == RoundOneSharingPartOne) {
            if (!(protocolMode_ == Unsecured)) {
                for (int slice = 0; slice < numSlices; slice++) {
                    // extract and decode the random values and the slice of the share
                    CryptoPP::Integer r(&rsMessage.body()[slice * 64], 32);
                    CryptoPP::Integer s(&rsMessage.body()[slice * 64 + 32], 32);

                    CryptoPP::ECPPoint commitment = commit(r, s);

                    // verify that the commitment is valid
                    if ((commitment.x != commitments_[rsMessage.senderID()][DCNetwork_.nodeID()][slice].x)
                        || (commitment.y != commitments_[rsMessage.senderID()][DCNetwork_.nodeID()][slice].y)) {
                        InitialRound::injectBlameMessage(rsMessage.senderID(), slice, r, s);
                        return -1;
                    }

                    R[slice] += r;
                    S[slice] += s;
                }
            } else {
                for (int slice = 0; slice < numSlices; slice++) {
                    CryptoPP::Integer s(&rsMessage.body()[slice * 32], 32);
                    S[slice] += s;
                }
            }
            remainingShares--;
        } else {
            DCNetwork_.inbox().push(rsMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    std::vector<uint8_t> rsVector;
    if(!(protocolMode_ == Unsecured)) {
        rsVector.resize(numSlices * 64);

        for (int i = 0; i < numSlices; i++) {
            R[i] = R[i].Modulo(curve_.GetSubgroupOrder());
            R[i].Encode(&rsVector[i * 64], 32);

            S[i] = S[i].Modulo(curve_.GetSubgroupOrder());
            S[i].Encode(&rsVector[i * 64 + 32], 32);
        }
    } else {
        rsVector.resize(numSlices * 32);

        for (int i = 0; i < numSlices; i++) {
            S[i] = S[i].Modulo(curve_.GetSubgroupOrder());
            S[i].Encode(&rsVector[i * 32], 32);
        }
    }

    for (auto &member : DCNetwork_.members()) {
        if (member.second.connectionID() != SELF) {
            OutgoingMessage rsBroadcast(member.second.connectionID(), RoundOneSharingPartTwo, DCNetwork_.nodeID(),
                                        rsVector);
            DCNetwork_.outbox().push(std::move(rsBroadcast));
        }
    }
    return 0;
}

std::vector<uint8_t> InitialRound::resultComputation() {
    size_t numSlices = S.size();
    // collect the added shares from the other k-1 members and validate them by adding the corresponding commitments
    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto rsBroadcast = DCNetwork_.inbox().pop();

        if (rsBroadcast.msgType() == RoundOneSharingPartTwo) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                 DCNetwork_.members().find(rsBroadcast.senderID()));

            if (!(protocolMode_ == Unsecured)) {
                for (int i = 0; i < numSlices; i++) {
                    // extract and decode the random values and the slice of the share
                    CryptoPP::Integer R_(&rsBroadcast.body()[i * 64], 32);
                    CryptoPP::Integer S_(&rsBroadcast.body()[i * 64 + 32], 32);

                    // validate r and s
                    CryptoPP::ECPPoint addedCommitments;
                    for (auto &c : commitments_)
                        addedCommitments = curve_.GetCurve().Add(addedCommitments, c.second[memberIndex][i]);

                    CryptoPP::ECPPoint commitment = commit(R_, S_);

                    if ((commitment.x != addedCommitments.x) || (commitment.y != addedCommitments.y)) {
                        // broadcast a blame message which contains the invalid share along with the corresponding r value
                        InitialRound::injectBlameMessage(rsBroadcast.senderID(), i, R_, S_);
                        return std::vector<uint8_t>();
                    }
                    R[i] += R_;
                    S[i] += S_;
                }
            } else {
                for (int i = 0; i < numSlices; i++) {
                    CryptoPP::Integer S_(&rsBroadcast.body()[i * 32], 32);
                    S[i] += S_;
                }
            }
            remainingShares--;
        } else if (rsBroadcast.msgType() == BlameMessage) {
            //InitialRound::handleBlameMessage(rsBroadcast);
            std::cout << "Blame message received" << std::endl;

            return std::vector<uint8_t>();
        } else {
            DCNetwork_.inbox().push(rsBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // validate the final commitments
    if (!(protocolMode_ == Unsecured)) {
        for (uint32_t slice = 0; slice < numSlices; slice++) {
            R[slice] = R[slice].Modulo(curve_.GetSubgroupOrder());
            S[slice] = S[slice].Modulo(curve_.GetSubgroupOrder());

            CryptoPP::ECPPoint commitment = commit(R[slice], S[slice]);

            if ((C[slice].x != commitment.x) || (C[slice].y != commitment.y)) {
                std::cout << "Invalid commitment detected" << std::endl;
                // TODO inject blame message
                return std::vector<uint8_t>();
            }
        }
    } else {
        for (int i = 0; i < numSlices; i++) {
            S[i] = S[i].Modulo(curve_.GetSubgroupOrder());
        }
    }

    // reconstruct the original message
    std::vector<uint8_t> reconstructedMessage;
    reconstructedMessage.resize(msgVector_.size());
    for (int i = 0; i < S.size(); i++) {
        size_t sliceSize = ((msgVector_.size() - 31 * i > 31) ? 31 : msgVector_.size() - 31 * i);
        S[i].Encode(&reconstructedMessage[31 * i], sliceSize);
    }

    //InitialRound::printMessageVector(reconstructedMessage);

    return reconstructedMessage;
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
void InitialRound::printMessageVector(std::vector<uint8_t> &msgVector) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << std::dec << "Node: " << DCNetwork_.nodeID() << std::endl;
    std::cout << "| ";
    for (int i = 0; i < 2 * k_; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[8 * i];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[8 * i + 1];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[8 * i + 2];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[8 * i + 3];
        std::cout << " ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[8 * i + 4];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[8 * i + 5];
        std::cout << " ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[8 * i + 6];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) msgVector[8 * i + 7];
        std::cout << " | ";
    }
    std::cout << std::endl << std::endl;
}




































