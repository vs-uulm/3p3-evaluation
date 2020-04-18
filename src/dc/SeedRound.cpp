#include <cryptopp/modes.h>
#include <cryptopp/oids.h>
#include <iostream>
#include <iomanip>
#include "DCNetwork.h"
#include "SeedRound.h"
#include "InitState.h"
#include "ReadyState.h"
#include "../datastruct/MessageType.h"
#include "SecuredInitialRound.h"
#include "SecuredFinalRound.h"

SeedRound::SeedRound(DCNetwork &DCNet, int slotIndex, std::vector<uint16_t> slots)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()), slotIndex_(slotIndex), slots_(std::move(slots)) {
    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

SeedRound::~SeedRound() {}

std::unique_ptr<DCState> SeedRound::executeTask() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Seed round" << std::endl;
    }
    size_t numSlots = slots_.size();

    size_t numSlices = std::ceil(33 * k_ / 31.0);

    std::vector<CryptoPP::Integer> messageSlices;
    if (slotIndex_ > -1) {
        std::vector<uint8_t> messageSlot(33 * k_);

        submittedSeeds_.reserve(k_);
        //CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryptAES;
        for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), it);

            std::array<uint8_t, 32> seed;
            //PRNG.GenerateBlock(seed.data(), 32);

            // generate an ephemeral EC key pair
            CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            CryptoPP::ECPPoint rG = curve_.ExponentiateBase(r);

            // Perform an ephemeral ECDH KE with the given public key
            CryptoPP::Integer sharedSecret = curve_.GetCurve().ScalarMultiply(it->second.publicKey(), r).x;
            sharedSecret.Encode(seed.data(), 32);

            //uint8_t keyIV[32];
            //sharedSecret.Encode(keyIV, 32);
            //encryptAES.SetKey(keyIV, 32);

            //encryptAES.ProcessData(&messageSlot[65 * memberIndex], seed.data(), 32);

            curve_.GetCurve().EncodePoint(&messageSlot[33 * memberIndex], rG, true);

            // store the seed
            submittedSeeds_.push_back(std::move(seed));
        }

        // Split the submitted message into slices of 31 Bytes
        messageSlices.reserve(numSlices);

        for (uint32_t i = 0; i < numSlices; i++) {
            size_t sliceSize = ((33 * k_ - 31 * i > 31) ? 31 : 33 * k_ - 31 * i);
            CryptoPP::Integer slice(&messageSlot[31 * i], sliceSize);
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

    // initialize the slices in the slots of the final share with the slices of the own share
    S.resize(numSlots);

    for (uint32_t slot = 0; slot < numSlots; slot++) {
        S[slot].reserve(numSlices);

        for (uint32_t slice = 0; slice < numSlices; slice++)
            S[slot].push_back(shares[slot][nodeIndex_][slice]);
    }

    // determine the total number of slices
    size_t totalNumSlices = 0;
    for (auto &slot : shares)
        totalNumSlices += slot[0].size();


    SeedRound::sharingPartOne(shares);

    int result = SeedRound::sharingPartTwo();
    // a blame message has been received
    if (result < 0) {
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    std::vector<std::vector<uint8_t>> finalSeeds = SeedRound::resultComputation();
    if ((finalSeeds.size() == 0) || (finalSeeds[0].size() == 0)) {
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    std::vector<std::array<uint8_t, 32>> receivedSeeds;
    for (uint32_t slot = 0; slot < numSlots; slot++) {

        //CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption decryptAES;
        //decrypt and extract the own seed for the each slot
        CryptoPP::ECPPoint rG;
        curve_.GetCurve().DecodePoint(rG, &finalSeeds[slot][33 * nodeIndex_], 33);

        // Perform an ephemeral ECDH KE with the given public key
        CryptoPP::Integer sharedSecret = curve_.GetCurve().ScalarMultiply(rG, DCNetwork_.privateKey()).x;

        std::array<uint8_t, 32> seed;
        sharedSecret.Encode(seed.data(), 32);

        //uint8_t keyIV[32];
        //sharedSecret.Encode(keyIV, 32);
        //decryptAES.SetKey(keyIV, 32);

        //std::array<uint8_t, 32> seed;
        //decryptAES.ProcessData(seed.data(), &finalSeeds[slot][65 * nodeIndex_], 32);

        receivedSeeds.push_back(std::move(seed));
    }

    return std::make_unique<SecuredFinalRound>(DCNetwork_, slotIndex_, std::move(slots_), std::move(submittedSeeds_),
                                               std::move(receivedSeeds));
}

void SeedRound::sharingPartOne(std::vector<std::vector<std::vector<CryptoPP::Integer>>> &shares) {
    size_t numSlots = slots_.size();
    size_t numSlices = std::ceil(33 * k_ / 31.0);

    R.resize(numSlots);
    C.resize(numSlots);

    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

    std::vector<std::vector<std::vector<uint8_t>>> encodedCommitments;
    encodedCommitments.resize(numSlots);

    std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitments;
    commitments.reserve(numSlots);

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues;

    rValues.resize(numSlots);
    for (auto &slot : rValues) {
        slot.resize(numSlices);
        for (auto &share : slot) {
            share.reserve(numSlices);
        }
    }

    for (uint32_t slot = 0; slot < numSlots; slot++) {
        encodedCommitments[slot].resize(k_);

        std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
        commitmentMatrix.resize(k_);
        for (auto &share : commitmentMatrix)
            share.reserve(numSlices);

        C[slot].resize(numSlices);
        R[slot].resize(numSlices);
        for (uint32_t share = 0; share < k_; share++) {
            encodedCommitments[slot][share].resize(2 + numSlices * encodedPointSize);
            // encode the current slot in the first two bytes
            encodedCommitments[slot][share][0] = (slot & 0xFF00) >> 8;
            encodedCommitments[slot][share][1] = slot & 0x00FF;
            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += encodedPointSize) {
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
                rValues[slot][share].push_back(std::move(r));
                // generate the commitment for the j-th slice of the i-th share
                CryptoPP::ECPPoint commitment = commit(rValues[slot][share][slice], shares[slot][share][slice]);
                // Add the commitment to the sum C
                C[slot][slice] = curve_.GetCurve().Add(C[slot][slice], commitment);

                if (share == nodeIndex_)
                    R[slot][slice] = rValues[slot][share][slice];

                // store the commitment
                commitmentMatrix[share].push_back(std::move(commitment));

                // compress the commitment and store in the given position in the vector
                curve_.GetCurve().EncodePoint(&encodedCommitments[slot][share][offset], commitmentMatrix[share][slice],
                                              true);
            }
        }
        commitments.push_back(std::move(commitmentMatrix));

    }
    commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitments)));

    // broadcast the commitments
    for (auto &member : DCNetwork_.members()) {
        if (member.second.connectionID() != SELF) {
            for (uint32_t slot = 0; slot < numSlots; slot++) {
                for (uint32_t share = 0; share < k_; share++) {
                    OutgoingMessage commitBroadcast(member.second.connectionID(), CommitmentSeedRound,
                                                    DCNetwork_.nodeID(), encodedCommitments[slot][share]);
                    DCNetwork_.outbox().push(std::move(commitBroadcast));
                }
            }
        }
    }

    // prepare the commitment storage
    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube;
        commitmentCube.resize(numSlots);
        for (auto &slot : commitmentCube)
            slot.reserve(k_);

        commitments_.insert(std::pair(member->second.nodeID(), std::move(commitmentCube)));
    }

    // collect the commitments from the other k-1 members
    uint32_t remainingCommitments = numSlots * k_ * (k_ - 1);
    while (remainingCommitments > 0) {
        auto commitBroadcast = DCNetwork_.inbox().pop();

        if (commitBroadcast.msgType() == CommitmentSeedRound) {

            std::vector<CryptoPP::ECPPoint> commitmentVector;
            commitmentVector.reserve(numSlices);

            // decode the slot and the share
            uint32_t slot = (commitBroadcast.body()[0] << 8) | (commitBroadcast.body()[1]);

            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += encodedPointSize) {
                CryptoPP::ECPPoint commitment;
                curve_.GetCurve().DecodePoint(commitment, &commitBroadcast.body()[offset],
                                              encodedPointSize);

                C[slot][slice] = curve_.GetCurve().Add(C[slot][slice], commitment);
                commitmentVector.push_back(std::move(commitment));
            }
            commitments_[commitBroadcast.senderID()][slot].push_back(std::move(commitmentVector));

            remainingCommitments--;
        } else {
            DCNetwork_.inbox().push(commitBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // distribute the shares to the individual members
    for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
        uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), it);

        if (it->second.connectionID() != SELF) {
            std::vector<uint8_t> sharingMessage;
            sharingMessage.resize(64 * numSlots * numSlices);

            for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                size_t numSlices = shares[slot][memberIndex].size();

                for (uint32_t slice = 0; slice < numSlices; slice++) {
                    rValues[slot][memberIndex][slice].Encode(&sharingMessage[offset], 32);
                    shares[slot][memberIndex][slice].Encode(&sharingMessage[offset + 32], 32);
                    offset += 64;
                }
            }

            OutgoingMessage rsMessage(it->second.connectionID(), SeedRoundSharingPartOne, DCNetwork_.nodeID(),
                                      sharingMessage);
            DCNetwork_.outbox().push(std::move(rsMessage));
        }
    }
}

int SeedRound::sharingPartTwo() {
    size_t numSlots = slots_.size();
    size_t numSlices = std::ceil(33 * k_ / 31.0);
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == SeedRoundSharingPartOne) {
            for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                size_t numSlices = S[slot].size();

                for (uint32_t slice = 0; slice < numSlices; slice++) {
                    CryptoPP::Integer r(&sharingMessage.body()[offset], 32);
                    CryptoPP::Integer s(&sharingMessage.body()[offset + 32], 32);
                    offset += 64;

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

            }
            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // construct the sharing broadcast which includes the added shares
    std::vector<uint8_t> sharingBroadcast;
    sharingBroadcast.resize(64 * numSlots * numSlices);

    for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
        for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
            S[slot][slice] = S[slot][slice].Modulo(curve_.GetSubgroupOrder());
            R[slot][slice] = R[slot][slice].Modulo(curve_.GetSubgroupOrder());

            R[slot][slice].Encode(&sharingBroadcast[offset], 32);
            S[slot][slice].Encode(&sharingBroadcast[offset] + 32, 32);
            offset += 64;
        }
    }

    // Broadcast the added shares in the DC network
    for (auto &member : DCNetwork_.members()) {
        if (member.second.connectionID() != SELF) {
            OutgoingMessage rsBroadcast(member.second.connectionID(), SeedRoundSharingPartTwo, DCNetwork_.nodeID(),
                                        sharingBroadcast);
            DCNetwork_.outbox().push(std::move(rsBroadcast));
        }
    }
    return 0;
}

std::vector<std::vector<uint8_t>> SeedRound::resultComputation() {
    size_t numSlots = S.size();

    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto sharingBroadcast = DCNetwork_.inbox().pop();

        if (sharingBroadcast.msgType() == SeedRoundSharingPartTwo) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                 DCNetwork_.members().find(sharingBroadcast.senderID()));

            for (uint32_t slot = 0, offset = 0; slot < numSlots; slot++) {
                for (uint32_t slice = 0; slice < S[slot].size(); slice++) {

                    CryptoPP::Integer S_(&sharingBroadcast.body()[offset + 32], 32);
                    CryptoPP::Integer R_(&sharingBroadcast.body()[offset], 32);
                    offset += 64;

                    R[slot][slice] += R_;

                    CryptoPP::ECPPoint C_;
                    for (auto &c : commitments_)
                        C_ = curve_.GetCurve().Add(C_, c.second[slot][memberIndex][slice]);

                    CryptoPP::ECPPoint commitment = commit(R_, S_);

                    // if the commitment is invalid, blame the sender
                    if ((commitment.x != C_.x) || (commitment.y != C_.y)) {
                        std::cout << "Invalid commitment detected" << std::endl;
                        //SeedRound::injectBlameMessage(sharingBroadcast.senderID(), slot, slice, S_);
                        return std::vector<std::vector<uint8_t>>();
                    }
                    S[slot][slice] += S_;
                }
            }
            remainingShares--;
        } else if (sharingBroadcast.msgType() == BlameMessage) {
            //SeedRound::handleBlameMessage(sharingBroadcast);
            return std::vector<std::vector<uint8_t>>();
        } else {
            DCNetwork_.inbox().push(sharingBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // final commitment validation
    for (uint32_t slot = 0; slot < numSlots; slot++) {
        for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
            S[slot][slice] = S[slot][slice].Modulo(curve_.GetSubgroupOrder());

            CryptoPP::ECPPoint commitment = commit(R[slot][slice], S[slot][slice]);

            if ((C[slot][slice].x != commitment.x) || (C[slot][slice].y != commitment.y)) {
                std::cout << "Invalid commitment detected" << std::endl;
            }
        }
    }

    // reconstruct the original message
    std::vector<std::vector<uint8_t>> reconstructedMessageSlots(numSlots);
    for (uint32_t slot = 0; slot < numSlots; slot++) {
        reconstructedMessageSlots[slot].resize(33 * k_);

        for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
            size_t sliceSize = ((33 * k_ - 31 * slice > 31) ? 31 : 33 * k_ - 31 * slice);
            S[slot][slice].Encode(&reconstructedMessageSlots[slot][31 * slice], sliceSize);
        }
    }

    return reconstructedMessageSlots;
}

inline CryptoPP::ECPPoint SeedRound::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve_.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = curve_.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = curve_.GetCurve().Add(rG, sH);
    return commitment;
}