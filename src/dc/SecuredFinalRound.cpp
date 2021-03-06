#include <iostream>
#include <cryptopp/oids.h>
#include <thread>
#include <iomanip>
#include "SecuredFinalRound.h"
#include "InitState.h"
#include "../datastruct/MessageType.h"
#include "SecuredInitialRound.h"
#include "../utils/Utils.h"
#include "BlameRound.h"
#include "../ad/VirtualSource.h"

std::mutex loggingMutex;

SecuredFinalRound::SecuredFinalRound(DCNetwork &DCNet, int slotIndex, std::vector<std::pair<uint16_t, uint16_t>> slots,
                                     std::vector<CryptoPP::Integer> seedPrivateKeys,
                                     std::vector<std::array<uint8_t, 32>> receivedSeeds)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()), slotIndex_(slotIndex), slots_(std::move(slots)),
          seedPrivateKeys_(seedPrivateKeys), seeds_(std::move(receivedSeeds)), rValues_(k_) {

    if(!DCNet.fullProtocol())
        delayedVerification_ = true;

    curve.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));

    R.resize(slots_.size());
    for (uint32_t slot = 0; slot < slots_.size(); slot++) {
        rValues_[slot].resize(k_);
        DRNG.SetKeyWithIV(seeds_[slot].data(), 16, seeds_[slot].data() + 16, 16);

        size_t numSlices = std::ceil((4 + slots_[slot].first) / 31.0);
        R[slot].resize(numSlices);
        for (uint32_t share = 0; share < k_; share++) {
            rValues_[slot][share].reserve(numSlices);

            for (uint32_t slice = 0; slice < numSlices; slice++) {
                CryptoPP::Integer r(DRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                rValues_[slot][share].push_back(std::move(r));

                if (share == nodeIndex_)
                    R[slot][slice] = rValues_[slot][nodeIndex_][slice];
            }
        }
    }
}

SecuredFinalRound::~SecuredFinalRound() {}

std::unique_ptr<DCState> SecuredFinalRound::executeTask() {
    std::vector<double> runtimes;
    auto start = std::chrono::high_resolution_clock::now();
    // generate the shares
    SecuredFinalRound::preparation();

    auto finished = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finished - start;
    runtimes.push_back(elapsed.count());

    start = std::chrono::high_resolution_clock::now();
    // generate and distribute the commitments and shares
    SecuredFinalRound::sharingPartOne();

    finished = std::chrono::high_resolution_clock::now();
    elapsed = finished - start;
    runtimes.push_back(elapsed.count());

    start = std::chrono::high_resolution_clock::now();
    // collect and validate the shares
    int result = SecuredFinalRound::sharingPartTwo();
    // a blame message has been received
    if (result < 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        DCNetwork_.inbox().clear();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return std::make_unique<InitState>(DCNetwork_);
    }
    finished = std::chrono::high_resolution_clock::now();
    elapsed = finished - start;
    runtimes.push_back(elapsed.count());

    start = std::chrono::high_resolution_clock::now();
    // collect and validate the final shares
    std::vector<std::vector<uint8_t>> finalMessages = SecuredFinalRound::resultComputation();

    if (finalMessages.size() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        DCNetwork_.inbox().clear();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return std::make_unique<InitState>(DCNetwork_);
    }

    // Verify the CRCs
    for(uint32_t slot = 0; slot < finalMessages.size(); slot++) {
        CRC32_.Update(&finalMessages[slot][4], finalMessages[slot].size() - 4);
        bool valid = CRC32_.Verify(finalMessages[slot].data());
        // if there is a CRC error in the own slot,
        // check which commitments don't add up to zero
        if(!valid && (static_cast<int>(slot) == slotIndex_)) {
            for (auto it = DCNetwork_.members().begin(); it != DCNetwork_.members().end(); it++) {
                uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), it);

                if (memberIndex != nodeIndex_) {
                    size_t numSlices = S[slotIndex_].size();

                    CryptoPP::Integer sharedSecret = curve.GetCurve().ScalarMultiply(it->second.publicKey(),
                                                                                     seedPrivateKeys_[memberIndex]).x;

                    std::array<uint8_t, 32> seed;
                    sharedSecret.Encode(seed.data(), 32);

                    DRNG.SetKeyWithIV(seed.data(), 16, seed.data() + 16, 16);

                    // calculate the rValues
                    std::vector<std::vector<CryptoPP::Integer>> rValues;
                    rValues.reserve(k_);

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
                        R_ = R_.Modulo(curve.GetGroupOrder());

                        // create the commitment
                        CryptoPP::Integer S_(CryptoPP::Integer::Zero());
                        CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, R_);
                        CryptoPP::ECPPoint sH = curve.GetCurve().ScalarMultiply(H, S_);
                        CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, sH);

                        // validate the commitment
                        if ((C_.x != commitment.x) || (C_.y != commitment.y)) {
                            // Switch to the blame protocol as a victim
                            return std::make_unique<BlameRound>(DCNetwork_, slotIndex_, slice, it->first,
                                                                seedPrivateKeys_[memberIndex], commitments_);
                        }
                    }
                }
            }
        }
        if (!valid) {
            // Switch to the blame protocol as a witness
            return std::make_unique<BlameRound>(DCNetwork_, commitments_);
        }
    }

    // Logging
    if (DCNetwork_.logging()) {
        finished = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = finished - start;
        double duration = elapsed.count();

        std::vector<uint8_t> log(4 * sizeof(double) + 4);
        // runtimes
        std::memcpy(&log[0], &runtimes[0], sizeof(double));
        std::memcpy(&log[8], &runtimes[1], sizeof(double));
        std::memcpy(&log[16], &runtimes[2], sizeof(double));
        std::memcpy(&log[24], &duration, sizeof(double));
        // security level
        log[4 * sizeof(double)] = (DCNetwork_.securityLevel() == Unsecured) ? 0 : 1;
        // round 2
        log[4 * sizeof(double) + 1] = 2;
        //sending
        log[4 * sizeof(double) + 2] = (slotIndex_ > -1) ? 1 : 0;
        //numThreads
        log[4 * sizeof(double) + 3] = DCNetwork_.numThreads();

        OutgoingMessage logMessage(CENTRAL, DCNetworkLogging, DCNetwork_.nodeID(), std::move(log));
        DCNetwork_.outbox().push(std::move(logMessage));
    }

    // print the reconstructed message slots
    {
        std::lock_guard<std::mutex> lock(loggingMutex);
        std::cout << "Node " << std::dec << DCNetwork_.nodeID() << " received messages:" << std::endl;
        for (auto &slot : finalMessages) {
            std::string msgHash = utils::sha256(slot);
            std::cout << "|";
            for (uint8_t c : msgHash) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
            }
            std::cout << "|" << std::endl;
        }
        std::cout << std::endl;
    }

    // pass the final message through the message handler to store it in the message buffer
    for (uint32_t t = 0; t < finalMessages.size(); t++) {
        std::vector<uint8_t> message(finalMessages[t].begin() + 4, finalMessages[t].end());
        OutgoingMessage finalMessage(SELF, DCNetworkReceived, SELF, std::move(message));
        DCNetwork_.outbox().push(std::move(finalMessage));

        // check if a VS Token has to be generated for this message by this node
        if(DCNetwork_.AD() && (slots_[t].second >= nodeIndex_*65535/k_) && (slots_[t].second < (nodeIndex_+1)*65535/k_)) {
            std::lock_guard<std::mutex> lock(loggingMutex);
            std::cout << "Node " << nodeIndex_ << "Generating VS Token for slot " << t << std::endl;
            std::vector<uint8_t> VSToken = VirtualSource::generateVSToken(0, 0, message);
            OutgoingMessage vsForward(SELF, VirtualSourceToken, DCNetwork_.nodeID(), VSToken);
            DCNetwork_.outbox().push(vsForward);
        }
    }

    return std::make_unique<SecuredInitialRound>(DCNetwork_);
}

void SecuredFinalRound::preparation() {
    size_t numSlots = slots_.size();

    std::vector<size_t> numSlices;
    numSlices.reserve(numSlots);
    // determine the number of slices for each slot individually
    for (uint32_t i = 0; i < numSlots; i++)
        numSlices.push_back(std::ceil((4 + slots_[i].first) / 31.0));

    std::vector<CryptoPP::Integer> messageSlices;

    if (slotIndex_ > -1) {
        std::vector<uint8_t> submittedMessage = DCNetwork_.submittedMessages().front();
        DCNetwork_.submittedMessages().pop();

        // Split the submitted message into slices of 31 Bytes
        messageSlices.reserve(numSlices[slotIndex_]);

        std::vector<uint8_t> messageSlot(4 + slots_[slotIndex_].first);
        // Calculate the CRC
        CRC32_.Update(submittedMessage.data(), slots_[slotIndex_].first);
        CRC32_.Final(messageSlot.data());

        std::copy(submittedMessage.begin(), submittedMessage.end(), &messageSlot[4]);

        for (uint32_t i = 0; i < numSlices[slotIndex_]; i++) {
            size_t sliceSize = ((messageSlot.size() - 31 * i > 31) ? 31 : messageSlot.size() - 31 * i);
            CryptoPP::Integer slice(&messageSlot[31 * i], sliceSize);
            messageSlices.push_back(std::move(slice));
        }
    }

    shares_.resize(numSlots);
    for (uint32_t slot = 0; slot < numSlots; slot++) {
        shares_[slot].resize(k_);

        // initialize the slices of the k-th share with zeroes
        // except the slices of the own message slot
        if (static_cast<uint32_t>(slotIndex_) == slot) {
            for (uint32_t slice = 0; slice < numSlices[slot]; slice++)
                shares_[slot][k_ - 1].push_back(messageSlices[slice]);
        } else {
            for (uint32_t slice = 0; slice < numSlices[slot]; slice++)
                shares_[slot][k_ - 1].push_back(CryptoPP::Integer::Zero());
        }

        // fill the first slices of the first k-1 shares with random values
        // and subtract the values from the corresponding slices in the k-th share
        for (uint32_t share = 0; share < k_ - 1; share++) {
            shares_[slot][share].reserve(numSlices[slot]);

            for (uint32_t slice = 0; slice < numSlices[slot]; slice++) {
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                // subtract the value from the corresponding slice in the k-th share
                shares_[slot][k_ - 1][slice] -= r;
                // store the random value in the slice of this share
                shares_[slot][share].push_back(std::move(r));
            }
        }

        // reduce the slices in the k-th share
        for (uint32_t slice = 0; slice < numSlices[slot]; slice++)
            shares_[slot][k_ - 1][slice] = shares_[slot][k_ - 1][slice].Modulo(curve.GetGroupOrder());
    }

    // initialize the slices in the slots of the final share with the slices of the own share
    S.resize(numSlots);

    for (uint32_t slot = 0; slot < numSlots; slot++) {
        S[slot].reserve(numSlices[slot]);

        for (uint32_t slice = 0; slice < numSlices[slot]; slice++)
            S[slot].push_back(shares_[slot][nodeIndex_][slice]);
    }
}

void SecuredFinalRound::sharingPartOne() {
    size_t numSlots = slots_.size();

    size_t encodedPointSize = curve.GetCurve().EncodedPointSize(true);

    std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube(numSlots);

    std::mutex threadMutex;
    std::list<std::thread> threads_;
    uint32_t currentSlot = 0;

    uint32_t numThreads = DCNetwork_.numThreads() > numSlots ? numSlots : DCNetwork_.numThreads();
    for (uint32_t t = 0; t < numThreads; t++) {
        std::thread commitThread([&]() {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve;
            threadCurve.Initialize(CryptoPP::ASN1::secp256k1());

            for (;;) {
                uint32_t slot;
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if (currentSlot < numSlots) {
                        slot = currentSlot;
                        currentSlot++;
                    } else {
                        break;
                    }
                }
                size_t numSlices = S[slot].size();

                std::vector<uint8_t> encodedCommitments(2 + k_ * numSlices * encodedPointSize);
                encodedCommitments[0] = (slot & 0xFF00) >> 8;
                encodedCommitments[1] = (slot & 0x00FF);

                std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix(k_);

                uint32_t offset = 2;
                for (uint32_t share = 0; share < k_; share++) {
                    commitmentMatrix[share].reserve(numSlices);
                    for (uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {

                        // generate the commitment for the j-th slice of the i-th share
                        CryptoPP::ECPPoint rG = threadCurve.GetCurve().ScalarMultiply(G, rValues_[slot][share][slice]);
                        CryptoPP::ECPPoint sH = threadCurve.GetCurve().ScalarMultiply(H, shares_[slot][share][slice]);
                        CryptoPP::ECPPoint commitment = threadCurve.GetCurve().Add(rG, sH);

                        // store the commitment
                        commitmentMatrix[share].push_back(std::move(commitment));

                        // compress the commitment and store in the given position in the vector
                        threadCurve.GetCurve().EncodePoint(&encodedCommitments[offset], commitmentMatrix[share][slice],
                                                           true);
                    }
                }
                std::lock_guard<std::mutex> lock(threadMutex);
                commitmentCube[slot] = std::move(commitmentMatrix);

                auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
                for (uint32_t member = 0; member < k_ - 1; member++) {
                    position++;
                    if (position == DCNetwork_.members().end())
                        position = DCNetwork_.members().begin();

                    OutgoingMessage commitBroadcast(position->second.connectionID(), FinalRoundCommitments,
                                                    DCNetwork_.nodeID(), encodedCommitments);
                    DCNetwork_.outbox().push(std::move(commitBroadcast));
                }
            }
        });
        threads_.push_back(std::move(commitThread));
    }

    // prepare the commitment storage
    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        if (member->first != DCNetwork_.nodeID()) {
            std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube(numSlots);

            commitments_.insert(std::pair(member->second.nodeID(), std::move(commitmentCube)));
        }
    }

    for (auto &t : threads_)
        t.join();

    commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitmentCube)));

    // collect the commitments from the other k-1 members
    threads_.clear();
    uint32_t remainingCommitments = numSlots * (k_ - 1);
    for (uint32_t t = 0; t < numThreads; t++) {
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

                if (commitBroadcast.msgType() == FinalRoundCommitments) {
                    std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
                    commitmentMatrix.reserve(k_);

                    // decode the slot
                    uint32_t slot = (commitBroadcast.body()[0] << 8) | (commitBroadcast.body()[1]);
                    size_t numSlices = S[slot].size();

                    uint32_t offset = 2;
                    for (uint32_t share = 0; share < k_; share++) {
                        std::vector<CryptoPP::ECPPoint> commitmentVector;
                        commitmentVector.reserve(numSlices);

                        for (uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {
                            CryptoPP::ECPPoint commitment;
                            threadCurve.GetCurve().DecodePoint(commitment, &commitBroadcast.body()[offset],
                                                               encodedPointSize);

                            commitmentVector.push_back(std::move(commitment));
                        }
                        commitmentMatrix.push_back(std::move(commitmentVector));
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
    for (uint32_t t = 0; t < numThreads; t++) {
        std::thread sharingThread([&]() {
            for (;;) {
                uint32_t slot;
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if (currentSlot < numSlots) {
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
                    size_t numSlices = S[slot].size();
                    std::vector<uint8_t> sharingMessage(2 + 64 * numSlices);
                    sharingMessage[0] = (slot & 0xFF00) >> 8;
                    sharingMessage[1] = (slot & 0x00FF);

                    for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
                        rValues_[slot][memberIndex][slice].Encode(&sharingMessage[offset], 32);
                        shares_[slot][memberIndex][slice].Encode(&sharingMessage[offset + 32], 32);
                    }

                    OutgoingMessage rsMessage(position->second.connectionID(), FinalRoundFirstSharing, DCNetwork_.nodeID(),
                                              sharingMessage);
                    DCNetwork_.outbox().push(std::move(rsMessage));
                }
            }
        });
        threads_.push_back(std::move(sharingThread));
    }

    for (auto &t : threads_)
        t.join();
}

int SecuredFinalRound::sharingPartTwo() {
    size_t numSlots = slots_.size();
    if(delayedVerification_) {
        rs_.reserve(k_-1);
        for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
            if (member->first != DCNetwork_.nodeID()) {
                std::vector<std::vector<std::pair<CryptoPP::Integer, CryptoPP::Integer>>> rsMatrix(numSlots);
                for(uint32_t slot = 0; slot < numSlots; slot++)
                    rsMatrix[slot].reserve(S[slot].size());
                rs_.insert(std::pair(member->second.nodeID(), std::move(rsMatrix)));
            }
        }
    }

    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    std::list<std::future<int>> futures_;
    std::mutex threadMutex;
    uint32_t remainingShares = numSlots * (k_ - 1);
    uint32_t numThreads = DCNetwork_.numThreads() > numSlots ? numSlots : DCNetwork_.numThreads();
    for (uint32_t t = 0; t < numThreads; t++) {
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

                if (sharingMessage.msgType() == FinalRoundFirstSharing) {

                    uint32_t slot = (sharingMessage.body()[0] << 8) | sharingMessage.body()[1];
                    size_t numSlices = S[slot].size();
                    for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
                        CryptoPP::Integer r(&sharingMessage.body()[offset], 32);
                        CryptoPP::Integer s(&sharingMessage.body()[offset + 32], 32);

                        if(delayedVerification_) {
                            rs_[sharingMessage.senderID()][slot].push_back(std::pair(r,s));
                        } else {
                            // verify that the corresponding commitment is valid
                            CryptoPP::ECPPoint rG = threadCurve.GetCurve().ScalarMultiply(G, r);
                            CryptoPP::ECPPoint sH = threadCurve.GetCurve().ScalarMultiply(H, s);
                            CryptoPP::ECPPoint commitment = threadCurve.GetCurve().Add(rG, sH);

                            // if the commitment is invalid, blame the sender
                            if ((commitment.x !=
                                 commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].x)
                                || (commitment.y !=
                                    commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].y)) {

                                SecuredFinalRound::injectBlameMessage(sharingMessage.senderID(), slot, slice, r, s);
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

    // construct the sharing broadcast which includes the added shares
    uint32_t currentSlot = 0;
    std::list<std::thread> threads_;
    for (uint32_t t = 0; t < numThreads; t++) {

        std::thread sharingThread([&]() {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve;
            threadCurve.Initialize(CryptoPP::ASN1::secp256k1());

            for (;;) {
                uint32_t slot;
                {
                    std::lock_guard<std::mutex> lock(threadMutex);
                    if (currentSlot < numSlots) {
                        slot = currentSlot;
                        currentSlot++;
                    } else {
                        break;
                    }
                }
                size_t numSlices = S[slot].size();
                std::vector<uint8_t> broadcastSlot(2 + 64 * numSlices);
                broadcastSlot[0] = (slot & 0xFF00) >> 8;
                broadcastSlot[1] = (slot & 0x00FF);

                for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
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

                    OutgoingMessage rsBroadcast(position->second.connectionID(), FinalRoundSecondSharing,
                                                DCNetwork_.nodeID(),
                                                broadcastSlot);
                    DCNetwork_.outbox().push(std::move(rsBroadcast));
                }
            }
        });
        threads_.push_back(std::move(sharingThread));
    }
    for (auto &t : threads_)
        t.join();
    return 0;
}

std::vector<std::vector<uint8_t>> SecuredFinalRound::resultComputation() {
    size_t numSlots = S.size();
    if(delayedVerification_) {
        RS_.reserve(k_-1);
        for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
            if (member->first != DCNetwork_.nodeID()) {
                std::vector<std::vector<std::pair<CryptoPP::Integer, CryptoPP::Integer>>> rsMatrix(numSlots);
                for(uint32_t slot = 0; slot < numSlots; slot++)
                    rsMatrix[slot].reserve(S[slot].size());
                RS_.insert(std::pair(member->second.nodeID(), std::move(rsMatrix)));
            }
        }
    }

    std::list<std::future<int>> futures_;
    std::mutex threadMutex;
    uint32_t remainingShares = numSlots * (k_ - 1);
    uint32_t numThreads = DCNetwork_.numThreads() > numSlots ? numSlots : DCNetwork_.numThreads();
    for (uint32_t t = 0; t < numThreads; t++) {
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

                if (rsBroadcast.msgType() == FinalRoundSecondSharing) {
                    uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                         DCNetwork_.members().find(rsBroadcast.senderID()));

                    uint32_t slot = (rsBroadcast.body()[0] << 8) | rsBroadcast.body()[1];
                    size_t numSlices = S[slot].size();
                    for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
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

                            CryptoPP::ECPPoint rG = threadCurve.GetCurve().ScalarMultiply(G, R_);
                            CryptoPP::ECPPoint sH = threadCurve.GetCurve().ScalarMultiply(H, S_);
                            CryptoPP::ECPPoint commitment = threadCurve.GetCurve().Add(rG, sH);

                            if ((commitment.x != addedCommitments.x) || (commitment.y != addedCommitments.y)) {
                                // broadcast a blame message which contains the invalid share along with the corresponding r values
                                std::cout << "Invalid commitment detected" << std::endl;
                                SecuredFinalRound::injectBlameMessage(rsBroadcast.senderID(), slot, slice, R_, S_);
                                std::lock_guard<std::mutex> lock(threadMutex);
                                remainingShares = 0;
                                return -1;
                            }
                        }
                        std::lock_guard<std::mutex> lock(threadMutex);
                        R[slot][slice] += R_;
                        S[slot][slice] += S_;
                    }

                } else if (rsBroadcast.msgType() == InvalidShare) {
                    SecuredFinalRound::handleBlameMessage(rsBroadcast);
                    std::cout << "Blame message received" << std::endl;
                    return -1;
                } else {
                    DCNetwork_.inbox().push(rsBroadcast);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    std::lock_guard<std::mutex> lock(threadMutex);
                    remainingShares++;
                }
            }
            return 0;
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

        OutgoingMessage finishedBroadcast(position->second.connectionID(), FinalRoundFinished,
                                          DCNetwork_.nodeID());
        DCNetwork_.outbox().push(std::move(finishedBroadcast));
    }

    // wait for the remaining nodes to finish the second sharing phase and catch potential blame messages
    uint32_t remainingNodes = k_-1;
    while(remainingNodes > 0) {
        auto message = DCNetwork_.inbox().pop();
        if(message.msgType() == FinalRoundFinished) {
            remainingNodes--;
        } else if(message.msgType() == InvalidShare){
            SecuredFinalRound::handleBlameMessage(message);
            std::cout << "Blame message received" << std::endl;
            return std::vector<std::vector<uint8_t>>();
        } else {
            DCNetwork_.inbox().push(message);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // reconstruct the original message
    std::vector<std::vector<uint8_t>> reconstructedMessageSlots(numSlots);
    for (uint32_t slot = 0; slot < numSlots; slot++) {
        reconstructedMessageSlots[slot].resize(4 + slots_[slot].first);

        for (uint32_t slice = 0; slice < S[slot].size(); slice++) {
            size_t sliceSize = ((4 + slots_[slot].first - 31 * slice > 31) ? 31 : 4 + slots_[slot].first - 31 * slice);
            S[slot][slice] = S[slot][slice].Modulo(curve.GetGroupOrder());
            S[slot][slice].Encode(&reconstructedMessageSlots[slot][31 * slice], sliceSize);
        }
    }
    return reconstructedMessageSlots;
}

void SecuredFinalRound::injectBlameMessage(uint32_t suspectID, uint32_t slot, uint32_t slice, CryptoPP::Integer &r,
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
    messageBody[6] = (slice & 0xFF000000) >> 24;
    messageBody[9] = (slice & 0x00FF0000) >> 16;
    messageBody[10] = (slice & 0x0000FF00) >> 8;
    messageBody[11] = (slice & 0x000000FF);

    // store the corrupt share
    r.Encode(&messageBody[12], 32);
    s.Encode(&messageBody[44], 32);

    for (auto &member : DCNetwork_.members()) {
        if (member.second.connectionID() != SELF) {
            OutgoingMessage blameMessage(member.second.connectionID(), InvalidShare, DCNetwork_.nodeID(), messageBody);
            DCNetwork_.outbox().push(blameMessage);
        }
    }
}


void SecuredFinalRound::handleBlameMessage(ReceivedMessage &blameMessage) {
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
    CryptoPP::ECPPoint rG = curve.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = curve.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = curve.GetCurve().Add(rG, sH);

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












