#include <iostream>
#include <thread>
#include <cryptopp/oids.h>
#include <numeric>
#include "SecuredInitialRound.h"
#include "DCNetwork.h"
#include "InitState.h"
#include "SecuredFinalRound.h"
#include "../datastruct/MessageType.h"

#include "FairnessProtocol.h"
#include "../utils/Utils.h"

SecuredInitialRound::SecuredInitialRound(DCNetwork &DCNet)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()), numSlices_(std::ceil((8 + 33 * k_) / 31.0)), slotIndex_(-1),
        delayedVerification_(true) {
    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
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

    std::vector<CryptoPP::Integer> messageSlices;

    std::vector<CryptoPP::Integer> seedPrivateKeys;

    if (l > 0) {
        std::vector<uint8_t> messageSlot(slotSize);
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        slotIndex_ = PRNG.GenerateWord32(0, 2 * k_ - 1);

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
        messageSlices.reserve(numSlices_);
        for (uint32_t i = 0; i < numSlices_; i++) {
            size_t sliceSize = ((slotSize - 31 * i > 31) ? 31 : slotSize - 31 * i);
            CryptoPP::Integer slice(&messageSlot[31 * i], sliceSize);
            messageSlices.push_back(std::move(slice));
        }
    }

    std::vector<std::vector<std::vector<CryptoPP::Integer>>> shares(2 * k_);
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        shares[slot].resize(k_);
        shares[slot][k_ - 1].reserve(numSlices_);
        // initialize the slices of the k-th share with zeroes
        // except the slices of the own message slot
        if (static_cast<uint32_t>(slotIndex_) == slot) {
            for (uint32_t slice = 0; slice < numSlices_; slice++)
                shares[slot][k_ - 1].push_back(messageSlices[slice]);
        } else {
            for (uint32_t slice = 0; slice < numSlices_; slice++)
                shares[slot][k_ - 1].push_back(CryptoPP::Integer::Zero());
        }

        // fill the first slices of the first k-1 shares with random values
        // and subtract the values from the corresponding slices in the k-th share
        for (uint32_t share = 0; share < k_ - 1; share++) {
            shares[slot][share].reserve(numSlices_);

            for (uint32_t slice = 0; slice < numSlices_; slice++) {
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
                // subtract the value from the corresponding slice in the k-th share
                shares[slot][k_ - 1][slice] -= r;
                // store the random value in the slice of this share
                shares[slot][share].push_back(std::move(r));
            }
        }

        // reduce the slices in the k-th share
        for (uint32_t slice = 0; slice < numSlices_; slice++)
            shares[slot][k_ - 1][slice] = shares[slot][k_ - 1][slice].Modulo(curve_.GetGroupOrder());
    }

    // store the slices of the own share in S
    S.resize(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        S[slot].reserve(numSlices_);
        for (uint32_t slice = 0; slice < numSlices_; slice++) {
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
    if(finalMessageVector.size() == 0) {
        // a blame message indicates that a member may have been excluded from the group
        // therefore a transition to the init state is performed,
        // which will execute a group membership protocol
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        DCNetwork_.inbox().clear();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return std::make_unique<InitState>(DCNetwork_);
    }

    // prepare the final round
    std::vector<uint16_t> slots;
    std::vector<std::array<uint8_t, 32>> receivedSeeds;

    // determine the non-empty slots in the message vector
    // and calculate the index of the own slot if present
    int finalSlotIndex = -1;
    uint32_t invalidCRCs = 0;
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        uint16_t slotSize = (finalMessageVector[slot][6] << 8) | finalMessageVector[slot][7];
        if (slotSize > 0) {
            // verify the CRC
            CRC32_.Update(&finalMessageVector[slot][4], 4 + 33 * k_);

            bool valid = CRC32_.Verify(finalMessageVector[slot].data());

            if(!valid) {
                invalidCRCs++;
            } else {
                if (static_cast<uint32_t>(slotIndex_) == slot)
                    finalSlotIndex = slots.size();

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
    }

    if(invalidCRCs > std::floor(k_/2)) {
        std::cout << "More than k/2 invalid CRCs detected." << std::endl;
        std::cout << "Switching to Proof of Fairness Protocol" << std::endl;
        return std::make_unique<FairnessProtocol>(DCNetwork_, numSlices_, slotIndex_, std::move(rValues_),
                                                  std::move(commitments_));
    }

    // Logging
    if (DCNetwork_.logging() && (slots.size() != 0) && (DCNetwork_.securityLevel() != ProofOfFairness)) {
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

    if (finalSlotIndex > -1)
        std::cout << "Node " << DCNetwork_.nodeID() << ": sending in slot " << std::dec << finalSlotIndex << std::endl;

    // for benchmarks only
    if(DCNetwork_.securityLevel() == ProofOfFairness)
        return std::make_unique<FairnessProtocol>(DCNetwork_, numSlices_, slotIndex_, std::move(rValues_),
                                                 std::move(commitments_));

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
    rValues_.resize(2 * k_);
    R.resize(2 * k_);

    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);
    std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube(2 * k_);

    std::mutex threadMutex;
    std::list<std::thread> threads_;
    uint32_t currentSlot = 0;
    for (uint32_t t = 0; t < DCNetwork_.numThreads(); t++) {
        std::thread commitThread([&]() {
            CryptoPP::AutoSeededRandomPool PRNG;
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve;
            threadCurve.Initialize(CryptoPP::ASN1::secp256k1());

            for(;;) {
                uint32_t slot;
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if(currentSlot < 2*k_) {
                        slot = currentSlot;
                        currentSlot++;
                    } else {
                        break;
                    }

                }

                rValues_[slot].resize(k_);
                R[slot].reserve(numSlices_);
                commitmentCube[slot].resize(k_);

                std::vector<uint8_t> encodedCommitments(2 + k_ * numSlices_ * encodedPointSize);
                encodedCommitments[0] = (slot & 0xFF00) >> 8;
                encodedCommitments[1] = (slot & 0x00FF);

                uint32_t offset = 2;
                for (uint32_t share = 0; share < k_; share++) {
                    rValues_[slot][share].reserve(numSlices_);
                    commitmentCube[slot][share].reserve(numSlices_);

                    for (uint32_t slice = 0; slice < numSlices_; slice++, offset += encodedPointSize) {

                        if(DCNetwork_.preparedCommitments().size() > 0 && (slot != slotIndex_)) {
                            // use the prepared values
                            rValues_[slot][share].push_back(DCNetwork_.preparedCommitments()[slot][share][slice].first);
                            commitmentCube[slot][share].push_back(DCNetwork_.preparedCommitments()[slot][share][slice].second);
                        } else {
                            CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), threadCurve.GetMaxExponent());
                            rValues_[slot][share].push_back(std::move(r));

                            CryptoPP::ECPPoint rG = threadCurve.GetCurve().Multiply(rValues_[slot][share][slice], G);
                            CryptoPP::ECPPoint sH = threadCurve.GetCurve().Multiply(shares[slot][share][slice], H);
                            CryptoPP::ECPPoint commitment = threadCurve.GetCurve().Add(rG, sH);

                            // store the commitment
                            commitmentCube[slot][share].push_back(std::move(commitment));
                        }
                        // add the rValue for the own share to the sum of rValues
                        if(share == nodeIndex_)
                            R[slot].push_back(rValues_[slot][nodeIndex_][slice]);

                        // compress the commitment and store in the given position in the vector
                        threadCurve.GetCurve().EncodePoint(&encodedCommitments[offset],
                                                           commitmentCube[slot][share][slice],
                                                           true);
                    }
                }

                auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
                for (uint32_t member = 0; member < k_ - 1; member++) {
                    position++;
                    if (position == DCNetwork_.members().end())
                        position = DCNetwork_.members().begin();

                    OutgoingMessage commitBroadcast(position->second.connectionID(), RoundOneCommitments,
                                                    DCNetwork_.nodeID(), encodedCommitments);
                    DCNetwork_.outbox().push(std::move(commitBroadcast));
                }
            }
        });
        threads_.push_back(std::move(commitThread));
    }

    // prepare the commitment storage

    commitments_.reserve(k_);
    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        if (member->first != DCNetwork_.nodeID()) {
            std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube(2*k_);

            commitments_.insert(std::pair(member->second.nodeID(), std::move(commitmentCube)));
        }
    }

    for (auto &t : threads_)
        t.join();

    commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitmentCube)));

    threads_.clear();
    uint32_t remainingCommitments = 2 * k_ * (k_ - 1);

    for (uint32_t t = 0; t < DCNetwork_.numThreads(); t++) {
        std::thread commitThread([&]() {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve;
            threadCurve.Initialize(CryptoPP::ASN1::secp256k1());

            for (;;) {
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if (remainingCommitments > 0)
                        remainingCommitments--;
                    else
                        break;
                }
                auto commitBroadcast = DCNetwork_.inbox().pop();
                if (commitBroadcast.msgType() == RoundOneCommitments) {

                    std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
                    commitmentMatrix.resize(k_);
                    for (auto &share : commitmentMatrix)
                        share.reserve(numSlices_);

                    uint32_t slot = (commitBroadcast.body()[0] << 8) | commitBroadcast.body()[1];
                    uint32_t offset = 2;
                    for (uint32_t share = 0; share < k_; share++) {
                        for (uint32_t slice = 0; slice < numSlices_; slice++, offset += encodedPointSize) {
                            CryptoPP::ECPPoint commitment;
                            threadCurve.GetCurve().DecodePoint(commitment, &commitBroadcast.body()[offset],
                                                               encodedPointSize);

                            commitmentMatrix[share].push_back(std::move(commitment));
                        }
                    }
                    std::lock_guard<std::mutex> lock(threadMutex);
                    commitments_[commitBroadcast.senderID()][slot] = std::move(commitmentMatrix);
                } else {
                    DCNetwork_.inbox().push(commitBroadcast);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));

                    std::lock_guard<std::mutex> lock(threadMutex);
                    remainingCommitments++;
                }
            }
        });
        threads_.push_back(std::move(commitThread));
    }

    for (auto &t : threads_)
        t.join();

    threads_.clear();

    currentSlot = 0;
    for (uint32_t t = 0; t < DCNetwork_.numThreads(); t++) {
        std::thread sharingThread([&]() {
            for(;;) {
                uint32_t slot;
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if(currentSlot < 2*k_) {
                        slot = currentSlot;
                        currentSlot++;
                    } else {
                        break;
                    }
                }
                auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
                for (uint32_t member = 0; member < k_ - 1; member++) {
                    position++;
                    if (position == DCNetwork_.members().end())
                        position = DCNetwork_.members().begin();

                    uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), position);
                    std::vector<uint8_t> sharingMessage(2 + 64 * numSlices_);
                    sharingMessage[0] = (slot & 0xFF00) >> 8;
                    sharingMessage[1] = (slot & 0x00FF);
                    for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 64) {
                        rValues_[slot][memberIndex][slice].Encode(&sharingMessage[offset], 32);
                        shares[slot][memberIndex][slice].Encode(&sharingMessage[offset + 32], 32);
                    }

                    OutgoingMessage rsMessage(position->second.connectionID(), RoundOneSharingOne, DCNetwork_.nodeID(),
                                              sharingMessage);
                    DCNetwork_.outbox().push(std::move(rsMessage));
                }
            }
        });
        threads_.push_back(std::move(sharingThread));
    }

    for(auto& t : threads_)
        t.join();
}

int SecuredInitialRound::sharingPartTwo() {
    if(delayedVerification_) {
        rs_.reserve(k_-1);
        for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
            if (member->first != DCNetwork_.nodeID()) {
                std::vector<std::vector<std::pair<CryptoPP::Integer, CryptoPP::Integer>>> rsMatrix(2*k_);
                for(uint32_t slot = 0; slot < 2*k_; slot++)
                    rsMatrix[slot].reserve(numSlices_);
                rs_.insert(std::pair(member->second.nodeID(), std::move(rsMatrix)));
            }
        }
    }
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    std::list<std::future<int>> futures_;
    std::mutex threadMutex;
    uint32_t remainingShares = 2 * k_ * (k_-1);

    for (uint32_t t = 0; t < DCNetwork_.numThreads(); t++) {
        std::future<int> future = std::async(std::launch::async, [&]() {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve;
            threadCurve.Initialize(CryptoPP::ASN1::secp256k1());

            for (;;) {
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if (remainingShares > 0)
                        remainingShares--;
                    else
                        break;
                }
                auto sharingMessage = DCNetwork_.inbox().pop();
                if (sharingMessage.msgType() == RoundOneSharingOne) {

                    uint32_t slot = (sharingMessage.body()[0] << 8) | sharingMessage.body()[1];

                    for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 64) {
                        CryptoPP::Integer r(&sharingMessage.body()[offset], 32);
                        CryptoPP::Integer s(&sharingMessage.body()[offset + 32], 32);

                        if(delayedVerification_) {
                            rs_[sharingMessage.senderID()][slot].push_back(std::pair(r,s));
                        } else {
                            // verify that the corresponding commitment is valid
                            CryptoPP::ECPPoint rG = threadCurve.GetCurve().Multiply(r, G);
                            CryptoPP::ECPPoint sH = threadCurve.GetCurve().Multiply(s, H);
                            CryptoPP::ECPPoint commitment = threadCurve.GetCurve().Add(rG, sH);

                            // if the commitment is invalid, blame the sender
                            if ((commitment.x !=
                                 commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].x)
                                || (commitment.y !=
                                    commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].y)) {

                                SecuredInitialRound::injectBlameMessage(sharingMessage.senderID(), slot, slice, r, s);

                                std::lock_guard<std::mutex> lock(threadMutex);
                                remainingShares = 0;
                                return -1;
                            }
                        }

                        std::lock_guard<std::mutex> lock(threadMutex);
                        R[slot][slice] += r;
                        S[slot][slice] += s;
                    }
                } else {
                    DCNetwork_.inbox().push(sharingMessage);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));

                    std::lock_guard<std::mutex> lock(threadMutex);
                    remainingShares++;
                }
            }
            return 0;
        });
        futures_.push_back(std::move(future));
    }

    // check if an invalid commitment has been detected
    for (auto &f : futures_)
        if (f.get() < 0)
            return -1;

    uint32_t currentSlot = 0;
    std::list<std::thread> threads_;
    for (uint32_t t = 0; t < DCNetwork_.numThreads(); t++) {

        std::thread sharingThread([&]() {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve;
            threadCurve.Initialize(CryptoPP::ASN1::secp256k1());

            for (;;) {
                uint32_t slot;
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if(currentSlot < 2*k_) {
                        slot = currentSlot;
                        currentSlot++;
                    } else {
                        break;
                    }
                }
                std::vector<uint8_t> broadcastSlot(2 + 64 * numSlices_);
                broadcastSlot[0] = (slot & 0xFF00) >> 8;
                broadcastSlot[1] = (slot & 0x00FF);

                for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 64) {
                    S[slot][slice] = S[slot][slice].Modulo(threadCurve.GetGroupOrder());
                    R[slot][slice] = R[slot][slice].Modulo(threadCurve.GetGroupOrder());

                    R[slot][slice].Encode(&broadcastSlot[offset], 32);
                    S[slot][slice].Encode(&broadcastSlot[offset] + 32, 32);
                }

                auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
                for (uint32_t member = 0; member < k_ - 1; member++) {
                    position++;
                    if (position == DCNetwork_.members().end())
                        position = DCNetwork_.members().begin();

                    OutgoingMessage rsBroadcast(position->second.connectionID(), RoundOneSharingTwo,
                                                DCNetwork_.nodeID(),
                                                broadcastSlot);
                    DCNetwork_.outbox().push(std::move(rsBroadcast));
                }
            }
        });
        threads_.push_back(std::move(sharingThread));
    }
    for(auto& t : threads_)
        t.join();

    return 0;
}

std::vector<std::vector<uint8_t>> SecuredInitialRound::resultComputation() {
    if(delayedVerification_) {
        RS_.reserve(k_-1);
        for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
            if (member->first != DCNetwork_.nodeID()) {
                std::vector<std::vector<std::pair<CryptoPP::Integer, CryptoPP::Integer>>> rsMatrix(2*k_);
                for(uint32_t slot = 0; slot < 2*k_; slot++)
                    rsMatrix[slot].reserve(numSlices_);
                RS_.insert(std::pair(member->second.nodeID(), std::move(rsMatrix)));
            }
        }
    }
    // collect the added shares from the other k-1 members and validate them by adding the corresponding commitments
    std::list<std::future<int>> futures_;
    std::mutex threadMutex;
    uint32_t remainingShares = 2 * k_ * (k_ - 1);
    for (uint32_t t = 0; t < DCNetwork_.numThreads(); t++) {
        std::future<int> future = std::async(std::launch::async, [&]() {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve;
            threadCurve.Initialize(CryptoPP::ASN1::secp256k1());

            for (;;) {
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if (remainingShares > 0)
                        remainingShares--;
                    else
                        return 0;
                }

                auto rsBroadcast = DCNetwork_.inbox().pop();

                if (rsBroadcast.msgType() == RoundOneSharingTwo) {
                    uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                         DCNetwork_.members().find(rsBroadcast.senderID()));

                    uint32_t slot = (rsBroadcast.body()[0] << 8) | rsBroadcast.body()[1];
                    for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 64) {
                        // extract and decode the random values and the slice of the share
                        CryptoPP::Integer R_(&rsBroadcast.body()[offset], 32);
                        CryptoPP::Integer S_(&rsBroadcast.body()[offset + 32], 32);

                        if(delayedVerification_) {
                            RS_[rsBroadcast.senderID()][slot].push_back(std::pair(R_,S_));
                        } else {
                            // validate r and s
                            CryptoPP::ECPPoint addedCommitments;
                            for (auto &c : commitments_)
                                addedCommitments = threadCurve.GetCurve().Add(addedCommitments,
                                                                              c.second[slot][memberIndex][slice]);

                            CryptoPP::ECPPoint rG = threadCurve.GetCurve().Multiply(R_, G);
                            CryptoPP::ECPPoint sH = threadCurve.GetCurve().Multiply(S_, H);
                            CryptoPP::ECPPoint commitment = threadCurve.GetCurve().Add(rG, sH);

                            if ((commitment.x != addedCommitments.x) || (commitment.y != addedCommitments.y)) {
                                // broadcast a blame message which contains the invalid share along with the corresponding r values
                                std::cout << "Invalid commitment detected" << std::endl;
                                SecuredInitialRound::injectBlameMessage(rsBroadcast.senderID(), slot, slice, R_, S_);
                                return -1;
                            }
                        }
                        std::lock_guard<std::mutex> lock(threadMutex);
                        R[slot][slice] += R_;
                        S[slot][slice] += S_;
                    }

                } else if (rsBroadcast.msgType() == InvalidShare) {
                    SecuredInitialRound::handleBlameMessage(rsBroadcast);
                    std::cout << "Blame message received" << std::endl;
                    return -1;
                } else {
                    DCNetwork_.inbox().push(rsBroadcast);
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    std::lock_guard<std::mutex> lock(threadMutex);
                    remainingShares++;
                }
            }
        });
        futures_.push_back(std::move(future));
    }

    // check if an invalid commitment has been detected in one of the threads
    for (auto &f : futures_)
        if (f.get() < 0)
            return std::vector<std::vector<uint8_t>>();


    // notify the other nodes that the execution was successful
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        OutgoingMessage finishedBroadcast(position->second.connectionID(), RoundOneFinished,
                                    DCNetwork_.nodeID());
        DCNetwork_.outbox().push(std::move(finishedBroadcast));
    }

    // wait for the remaining nodes to finish the second sharing phase and catch potential blame messages
    uint32_t remainingNodes = k_-1;
    while(remainingNodes > 0) {
        auto message = DCNetwork_.inbox().pop();
        if(message.msgType() == RoundOneFinished) {
            remainingNodes--;
        } else if(message.msgType() == InvalidShare){
            SecuredInitialRound::handleBlameMessage(message);
            std::cout << "Blame message received" << std::endl;
            return std::vector<std::vector<uint8_t>>();
        } else {
            DCNetwork_.inbox().push(message);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // reconstruct the original message
    std::vector<std::vector<uint8_t>> finalMessageSlots;
    finalMessageSlots.resize(2 * k_);

    uint32_t currentSlot = 0;
    std::list<std::thread> threads_;
    for (uint32_t t = 0; t < DCNetwork_.numThreads(); t++) {
        std::thread computeThread([&]() {
            uint32_t slot;
            for (;;) {
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if(currentSlot < 2*k_) {
                        slot = currentSlot;
                        currentSlot++;
                    } else {
                        break;
                    }
                }
                finalMessageSlots[slot].resize(8 + 33 * k_);
                for (uint32_t slice = 0; slice < numSlices_; slice++) {
                    S[slot][slice] = S[slot][slice].Modulo(curve_.GetGroupOrder());
                    size_t sliceSize = (((8 + 33 * k_) - 31 * slice > 31) ? 31 : (8 + 33 * k_) - 31 * slice);
                    S[slot][slice].Encode(&finalMessageSlots[slot][31 * slice], sliceSize);
                }
            }
        });
        threads_.push_back(std::move(computeThread));
    }

    for (auto &t : threads_)
        t.join();

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
            OutgoingMessage blameMessage(member.second.connectionID(), InvalidShare, DCNetwork_.nodeID(), messageBody);
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
    CryptoPP::ECPPoint rG = curve_.GetCurve().Multiply(r, G);
    CryptoPP::ECPPoint sH = curve_.GetCurve().Multiply(s, H);
    CryptoPP::ECPPoint commitment = curve_.GetCurve().Add(rG, sH);

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

































