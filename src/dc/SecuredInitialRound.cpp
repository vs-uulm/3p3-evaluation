#include <iostream>
#include <thread>
#include <cryptopp/oids.h>
#include <iomanip>
#include <numeric>
#include "SecuredInitialRound.h"
#include "DCNetwork.h"
#include "InitState.h"
#include "SecuredFinalRound.h"
#include "../datastruct/MessageType.h"

#include "FairnessProtocol.h"
#include "../utils/Utils.h"

std::mutex mutex_;

SecuredInitialRound::SecuredInitialRound(DCNetwork &DCNet)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()) {
    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));

    //std::cout << "Initial Round" << std::endl;
}

SecuredInitialRound::~SecuredInitialRound() {}

std::unique_ptr<DCState> SecuredInitialRound::executeTask() {
    std::vector<double> runtimes;
    auto start = std::chrono::high_resolution_clock::now();
    // check if there is a submitted message and determine it's length,
    // but don't remove it from the message queue just yet
    uint16_t l = 0;
    if (!DCNetwork_.submittedMessages().empty()) {
        size_t msgSize = DCNetwork_.submittedMessages().front().size();
        // ensure that the message size does not exceed 2^16 Bytes
        l = msgSize > USHRT_MAX ? USHRT_MAX : msgSize;
    }

    size_t slotSize = 8 + 33 * k_;
    size_t numSlices = std::ceil(slotSize / 31.0);

    std::vector<CryptoPP::Integer> messageSlices;

    std::vector<CryptoPP::Integer> seedPrivateKeys;
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
        seedPrivateKeys.reserve(k_);
        for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), it);

            // generate an ephemeral EC key pair
            CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            CryptoPP::ECPPoint rG = curve_.ExponentiateBase(r);

            curve_.GetCurve().EncodePoint(&messageSlot[8 + 33 * memberIndex], rG, true);

            // store the seed
            seedPrivateKeys.push_back(std::move(r));
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
        shares[slot][k_ - 1].reserve(numSlices);
        // initialize the slices of the k-th share with zeroes
        // except the slices of the own message slot
        if (static_cast<uint32_t>(slotIndex) == slot) {
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
            shares[slot][k_ - 1][slice] = shares[slot][k_ - 1][slice].Modulo(curve_.GetGroupOrder());
    }

    // store the slices of the own share in S
    S.resize(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        S[slot].reserve(numSlices);
        for (uint32_t slice = 0; slice < numSlices; slice++) {
            S[slot].push_back(shares[slot][nodeIndex_][slice]);
        }
    }
    // logging
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    // generate and broadcast the commitments for the first round
    SecuredInitialRound::sharingPartOne(shares);

    // logging
    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    // collect and validate the shares
    int result = SecuredInitialRound::sharingPartTwo();
    // a blame message has been received
    if (result < 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        DCNetwork_.inbox().clear();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return std::make_unique<InitState>(DCNetwork_);
    }

    // logging
    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    // collect and validate the final shares
    std::vector<std::vector<uint8_t>> finalMessageVector = SecuredInitialRound::resultComputation();
    // Check if the protocol's execution has been interrupted by a blame message
    if (finalMessageVector.size() == 0) {
        // a blame message indicates that a member may have been excluded from the group
        // therefore a transition to the init state is performed,
        // which will execute a group membership protocol
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        DCNetwork_.inbox().clear();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return std::make_unique<InitState>(DCNetwork_);
    }

    // prepare round two
    std::vector<uint16_t> slots;
    std::vector<std::array<uint8_t, 32>> receivedSeeds;

    // determine the non-empty slots in the message vector
    // and calculate the index of the own slot if present
    int finalSlotIndex = -1;
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        if (static_cast<uint32_t>(slotIndex) == slot)
            finalSlotIndex = slots.size();

        uint16_t slotSize = (finalMessageVector[slot][6] << 8) | finalMessageVector[slot][7];
        if (slotSize > 0) {
            // verify the CRC
            CRC32_.Update(&finalMessageVector[slot][4], 4 + 33 * k_);

            bool valid = CRC32_.Verify(finalMessageVector[slot].data());

            if (!valid) {
                std::cout << "Invalid CRC detected." << std::endl;
                std::cout << "Restarting Round One." << std::endl;
                return std::make_unique<SecuredInitialRound>(DCNetwork_);
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

    if (finalSlotIndex > -1) {
        std::cout << "Node " << DCNetwork_.nodeID() << ": sending in slot " << std::dec << finalSlotIndex << std::endl
                  << std::endl;
    }

    // TODO undo
    // coin flip test
    bool coinFlipTest = false;
    if (coinFlipTest)
        return std::make_unique<FairnessProtocol>(DCNetwork_, numSlices, slotIndex, std::move(rValues_),
                                                  std::move(commitments_));

    // Logging
    if (DCNetwork_.logging() && (slots.size() != 0)) {
        auto finish = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = finish - start;
        double duration = elapsed.count();

        std::vector<uint8_t> log(4 * sizeof(double) + 4);
        // runtimes
        std::memcpy(&log[0], &runtimes[0], sizeof(double));
        std::memcpy(&log[8], &runtimes[1], sizeof(double));
        std::memcpy(&log[16], &runtimes[2], sizeof(double));
        std::memcpy(&log[24], &duration, sizeof(double));
        // security level
        log[4 * sizeof(double)] = (DCNetwork_.securityLevel() == Unsecured) ? 0 : 1;
        // round 1
        log[4 * sizeof(double) + 1] = 1;
        //sending
        log[4 * sizeof(double) + 2] = (finalSlotIndex > -1) ? 1 : 0;
        //numThreads
        log[4 * sizeof(double) + 3] = DCNetwork_.numThreads();

        OutgoingMessage logMessage(CENTRAL, DCLoggingMessage, DCNetwork_.nodeID(), std::move(log));
        DCNetwork_.outbox().push(std::move(logMessage));
    }

    // if no member wants to send a message, return to the Ready state
    if (slots.size() == 0) {
        std::cout << "No sender in this round" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return std::make_unique<SecuredInitialRound>(DCNetwork_);
    } else {
        return std::make_unique<SecuredFinalRound>(DCNetwork_, finalSlotIndex, std::move(slots),
                                                   std::move(seedPrivateKeys),
                                                   std::move(receivedSeeds));
    }
}

void SecuredInitialRound::sharingPartOne(std::vector<std::vector<std::vector<CryptoPP::Integer>>> &shares) {
    size_t numSlices = std::ceil((8 + 33 * k_) / 31.0);

    rValues_.resize(2 * k_);
    C.resize(2 * k_);
    R.resize(2 * k_);

    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);
    std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube(2 * k_);
    std::vector<std::vector<std::vector<uint8_t>>> encodedCommitmentCube(2 * k_);

    std::list<std::thread> threads_;
    for (uint32_t t = 0; t < DCNetwork_.numThreads(); t++) {
        uint32_t first = 2 * k_ / static_cast<double>(DCNetwork_.numThreads()) * t;
        uint32_t last = 2 * k_ / static_cast<double>(DCNetwork_.numThreads()) * (t + 1);

        std::thread commitThread([&, first, last]() {
            CryptoPP::AutoSeededRandomPool threadPRNG;
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve;
            threadCurve.Initialize(CryptoPP::ASN1::secp256k1());
            std::vector<CryptoPP::ECPPoint> vec;

            for (uint32_t slot = first; slot < last; slot++) {
                rValues_[slot].resize(k_);
                R[slot].reserve(numSlices);
                C[slot].resize(numSlices);

                //std::vector<std::vector<uint8_t>> encodedCommitmentMatrix(k_);
                encodedCommitmentCube[slot].resize(k_);
                commitmentCube[slot].resize(k_);

                for (uint32_t share = 0; share < k_; share++) {
                    rValues_[slot][share].reserve(numSlices);
                    commitmentCube[slot][share].reserve(numSlices);
                    encodedCommitmentCube[slot][share].resize(2 + numSlices * encodedPointSize);

                    // encode the current slot in the first two bytes
                    encodedCommitmentCube[slot][share][0] = (slot & 0xFF00) >> 8;
                    encodedCommitmentCube[slot][share][1] = (slot & 0x00FF);
                    for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += encodedPointSize) {
                        // generate the random value r for this slice of the share
                        CryptoPP::Integer r(threadPRNG, CryptoPP::Integer::One(), threadCurve.GetMaxExponent());
                        rValues_[slot][share].push_back(std::move(r));

                        CryptoPP::ECPPoint rG = threadCurve.GetCurve().Multiply(rValues_[slot][share][slice], G);
                        CryptoPP::ECPPoint sH = threadCurve.GetCurve().Multiply(shares[slot][share][slice], H);
                        CryptoPP::ECPPoint commitment = threadCurve.GetCurve().Add(rG, sH);

                        // store the commitment
                        commitmentCube[slot][share].push_back(std::move(commitment));

                        // compress the commitment and store in the given position in the vector
                        threadCurve.GetCurve().EncodePoint(&encodedCommitmentCube[slot][share][offset],
                                                           commitmentCube[slot][share][slice],
                                                           true);

                        // Add the commitment to the sum C
                        C[slot][slice] = threadCurve.GetCurve().Add(C[slot][slice], commitmentCube[slot][share][slice]);
                    }
                }
            }
        });
        threads_.push_back(std::move(commitThread));
    }
    for (auto &t : threads_)
        t.join();



// broadcast the commitments for this slot
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2 * k_; slot++) {
            for (uint32_t share = 0; share < k_; share++) {
                OutgoingMessage commitBroadcast(position->second.connectionID(), RoundOneCommitments,
                                                DCNetwork_.nodeID(), encodedCommitmentCube[slot][share]);
                DCNetwork_.outbox().push(std::move(commitBroadcast));
            }
        }
    }

    // store the commitment matrix
    commitments_.reserve(k_);
    commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitmentCube)));


    // get the index of the own share by checking the position of the local nodeID in the member list
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        for (uint32_t slice = 0; slice < numSlices; slice++) {
            R[slot].push_back(rValues_[slot][nodeIndex_][slice]);
        }
    }

    // prepare the commitment storage
    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube;
        commitmentCube.resize(2 * k_);

        for (auto &slot : commitmentCube)
            slot.reserve(k_);

        commitments_.insert(std::pair(member->second.nodeID(), std::move(commitmentCube)));
    }

    // collect the commitments from the other k-1 members
    uint32_t remainingCommitments = 2 * k_ * k_ * (k_ - 1);
    while (remainingCommitments > 0) {
        auto commitBroadcast = DCNetwork_.inbox().pop();
        if (commitBroadcast.msgType() == RoundOneCommitments) {

            // decode the slot and the share
            uint32_t slot = (commitBroadcast.body()[0] << 8) | (commitBroadcast.body()[1]);

            std::vector<CryptoPP::ECPPoint> commitmentVector;
            commitmentVector.reserve(numSlices);

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
                rValues_[slot][memberIndex][slice].Encode(&sharingMessage[offset], 32);
                shares[slot][memberIndex][slice].Encode(&sharingMessage[offset + 32], 32);
            }

            OutgoingMessage rsMessage(position->second.connectionID(), RoundOneSharingOne, DCNetwork_.nodeID(),
                                      sharingMessage);
            DCNetwork_.outbox().push(std::move(rsMessage));
        }
    }
}

int SecuredInitialRound::sharingPartTwo() {
    size_t numSlices = std::ceil((8 + 33 * k_) / 31.0);
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = 2 * k_ * (k_ - 1);
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == RoundOneSharingOne) {

            uint32_t slot = (sharingMessage.body()[0] << 8) | sharingMessage.body()[1];

            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
                CryptoPP::Integer r(&sharingMessage.body()[offset], 32);
                CryptoPP::Integer s(&sharingMessage.body()[offset + 32], 32);

                // verify that the corresponding commitment is valid
                CryptoPP::ECPPoint commitment = commit(r, s);
                // if the commitment is invalid, blame the sender
                if ((commitment.x != commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].x)
                    || (commitment.y != commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].y)) {

                    SecuredInitialRound::injectBlameMessage(sharingMessage.senderID(), slot, slice, r, s);
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
            S[slot][slice] = S[slot][slice].Modulo(curve_.GetGroupOrder());
            R[slot][slice] = R[slot][slice].Modulo(curve_.GetGroupOrder());

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
            OutgoingMessage rsBroadcast(position->second.connectionID(), RoundOneSharingTwo, DCNetwork_.nodeID(),
                                        sharingBroadcast[slot]);
            DCNetwork_.outbox().push(std::move(rsBroadcast));
        }
    }

    return 0;
}

std::vector<std::vector<uint8_t>> SecuredInitialRound::resultComputation() {
    size_t numSlices = std::ceil((8 + 33 * k_) / 31.0);
    // collect the added shares from the other k-1 members and validate them by adding the corresponding commitments
    uint32_t remainingShares = 2 * k_ * (k_ - 1);
    while (remainingShares > 0) {
        auto rsBroadcast = DCNetwork_.inbox().pop();

        if (rsBroadcast.msgType() == RoundOneSharingTwo) {
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
                    SecuredInitialRound::injectBlameMessage(rsBroadcast.senderID(), slot, slice, R_, S_);
                    return std::vector<std::vector<uint8_t>>();
                }
                R[slot][slice] += R_;
                S[slot][slice] += S_;
            }

            remainingShares--;
        } else if (rsBroadcast.msgType() == BlameMessage) {
            SecuredInitialRound::handleBlameMessage(rsBroadcast);
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
            R[slot][slice] = R[slot][slice].Modulo(curve_.GetGroupOrder());
            S[slot][slice] = S[slot][slice].Modulo(curve_.GetGroupOrder());

            CryptoPP::ECPPoint commitment = commit(R[slot][slice], S[slot][slice]);

            if ((C[slot][slice].x != commitment.x) || (C[slot][slice].y != commitment.y)) {
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

    return finalMessageSlots;
}

void SecuredInitialRound::injectBlameMessage(uint32_t suspectID, uint32_t slot, uint32_t slice, CryptoPP::Integer &r,
                                             CryptoPP::Integer &s) {
    std::vector<uint8_t> messageBody(76);
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
    messageBody[8] = (slice & 0xFF000000) >> 24;
    messageBody[9] = (slice & 0x00FF0000) >> 16;
    messageBody[10] = (slice & 0x0000FF00) >> 8;
    messageBody[11] = (slice & 0x000000FF);

    // store the r and s value
    r.Encode(&messageBody[12], 32);
    s.Encode(&messageBody[44], 32);

    for (auto &member : DCNetwork_.members()) {
        if (member.second.connectionID() != SELF) {
            OutgoingMessage blameMessage(member.second.connectionID(), BlameMessage, DCNetwork_.nodeID(), messageBody);
            DCNetwork_.outbox().push(std::move(blameMessage));
        }
    }
}

void SecuredInitialRound::handleBlameMessage(ReceivedMessage &blameMessage) {
    std::vector<uint8_t> &body = blameMessage.body();
    // check which node is addressed by the blame message
    uint32_t suspectID = (body[0] << 24) | (body[1] << 16) | (body[2] << 8) | body[3];

    // extract the index of the slot
    uint32_t slot = (body[4] << 24) | (body[5] << 16) | (body[6] << 8) | body[7];

    // extract the index of the corrupted slice
    uint32_t slice = (body[8] << 24) | (body[9] << 16) | (body[10] << 8) | body[11];

    // extract the the corrupted slice
    CryptoPP::Integer r(&body[12], 32);
    CryptoPP::Integer s(&body[44], 32);

    // validate that the slice is actually corrupt
    CryptoPP::ECPPoint commitment = commit(r, s);

    uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                         DCNetwork_.members().find(suspectID));

    // compare the commitment, generated using the submitted values, with the commitment
    // which has been broadcasted by the suspect
    if ((commitment.x != commitments_[suspectID][slot][memberIndex][slice].x)
        || (commitment.y != commitments_[suspectID][slot][memberIndex][slice].y)) {
        // if the two commitments do not match, the suspect is removed
        DCNetwork_.members().erase(suspectID);
    } else {
        // if the two commitments match, the sender is removed
        DCNetwork_.members().erase(blameMessage.senderID());
    }
}

inline CryptoPP::ECPPoint SecuredInitialRound::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve_.GetCurve().Multiply(r, G);
    CryptoPP::ECPPoint sH = curve_.GetCurve().Multiply(s, H);
    CryptoPP::ECPPoint commitment = curve_.GetCurve().Add(rG, sH);
    return commitment;
}

// helper function to print the slots in the message vector
void SecuredInitialRound::printSlots(std::vector<std::vector<uint8_t>> &slots) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << std::dec << "Node: " << DCNetwork_.nodeID() << std::endl;
    std::cout << "| ";
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
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

































