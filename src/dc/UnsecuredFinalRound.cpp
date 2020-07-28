#include <iomanip>
#include "UnsecuredFinalRound.h"
#include "DCNetwork.h"
#include "../datastruct/MessageType.h"
#include "SecuredInitialRound.h"
#include "../utils/Utils.h"
#include "UnsecuredInitialRound.h"

UnsecuredFinalRound::UnsecuredFinalRound(DCNetwork &DCNet, int slotIndex, std::vector<uint16_t> slots)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()), slotIndex_(slotIndex), slots_(std::move(slots)) {

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

UnsecuredFinalRound::~UnsecuredFinalRound() {}

std::unique_ptr<DCState> UnsecuredFinalRound::executeTask() {
    std::vector<double> runtimes;
    auto start = std::chrono::high_resolution_clock::now();
    size_t numSlots = slots_.size();

    std::vector<uint8_t> submittedMessage;
    if (slotIndex_ > -1) {
        submittedMessage = DCNetwork_.submittedMessages().front();
        DCNetwork_.submittedMessages().pop();
    }

    // initialize the slices in the slots of the final share with the slices of the own share
    S.reserve(numSlots);

    std::vector<std::vector<std::vector<uint8_t>>> shares(numSlots);

    for (uint32_t slot = 0; slot < numSlots; slot++) {
        shares[slot].resize(k_);

        shares[slot][k_ - 1].resize(4 + slots_[slot]);
        if (static_cast<uint32_t>(slotIndex_) == slot) {
            // Calculate the CRC
            CRC32_.Update(submittedMessage.data(), submittedMessage.size());
            CRC32_.Final(shares[slot][k_ - 1].data());

            std::copy(submittedMessage.begin(), submittedMessage.end(), &shares[slot][k_ - 1][4]);
        }

        for (uint32_t share = 0; share < k_ - 1; share++) {
            shares[slot][share].resize(4 + slots_[slot]);
            PRNG.GenerateBlock(shares[slot][share].data(), 4 + slots_[slot]);

            // XOR The value to the final share
            for (uint32_t p = 0; p < 4 + static_cast<uint32_t>(slots_[slot]); p++)
                shares[slot][k_ - 1][p] ^= shares[slot][share][p];
        }

        S.push_back(shares[slot][nodeIndex_]);
    }

    // logging
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    UnsecuredFinalRound::sharingPartOne(shares);

    // logging
    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    UnsecuredFinalRound::sharingPartTwo();

    // logging
    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();
    UnsecuredFinalRound::resultComputation();
    // Logging
    if (DCNetwork_.logging()) {
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
        log[4 * sizeof(double) + 1] = 2;
        //sending
        log[4 * sizeof(double) + 2] = (slotIndex_ > -1) ? 1 : 0;
        //numThreads
        log[4 * sizeof(double) + 3] = DCNetwork_.numThreads();

        OutgoingMessage logMessage(CENTRAL, DCLoggingMessage, DCNetwork_.nodeID(), std::move(log));
        DCNetwork_.outbox().push(std::move(logMessage));
    }

    {
        std::cout << "Node: " << std::dec << DCNetwork_.nodeID() << std::endl;
        for (auto &slot : S) {
            std::string msgHash = utils::sha256(slot);
            std::cout << "|";
            for (uint8_t c : msgHash) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
            }
            std::cout << "|" << std::endl;
        }
        std::cout << std::endl;
    }

    // Verify the CRCs
    for(auto& slot : S) {
        CRC32_.Update(&slot[4], slot.size() - 4);
        bool valid = CRC32_.Verify(slot.data());
        if(!valid) {
            // Switch to the secured version
            return std::make_unique<SecuredInitialRound>(DCNetwork_);
        }
    }

    // hand the messages to upper level
    for(auto& slot : S) {
        std::vector<uint8_t> message(slot.begin() + 4, slot.end());
        OutgoingMessage finalMessage(SELF, FinalDCMessage, SELF, std::move(message));
        DCNetwork_.outbox().push(std::move(finalMessage));
    }
    std::this_thread::sleep_for(std::chrono::seconds(DCNetwork_.interval()));
    return std::make_unique<UnsecuredInitialRound>(DCNetwork_);
}

void UnsecuredFinalRound::sharingPartOne(std::vector<std::vector<std::vector<uint8_t>>> &shares) {
    size_t numSlots = slots_.size();

    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), position);

        for (uint32_t slot = 0; slot < numSlots; slot++) {
            std::vector<uint8_t> share(6 + slots_[slot]);
            share[0] = (slot & 0xFF00) >> 8;
            share[1] = (slot & 0x00FF);
            std::copy(shares[slot][memberIndex].begin(), shares[slot][memberIndex].end(), &share[2]);
            OutgoingMessage sharingMessage(position->second.connectionID(), FinalRoundFirstSharing, DCNetwork_.nodeID(),
                                           share);
            DCNetwork_.outbox().push(std::move(sharingMessage));
        }
    }
}

void UnsecuredFinalRound::sharingPartTwo() {
    size_t numSlots = slots_.size();

    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = numSlots * (k_ - 1);
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == FinalRoundFirstSharing) {

            size_t slot = (sharingMessage.body()[0] << 8) | sharingMessage.body()[1];
            for (uint32_t p = 0; p < 4 + static_cast<uint32_t>(slots_[slot]); p++)
                S[slot][p] ^= sharingMessage.body()[p+2];

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < numSlots; slot++) {
            std::vector<uint8_t> addedShares(6 + slots_[slot]);
            addedShares[0] = (slot & 0xFF00) >> 8;
            addedShares[1] = (slot & 0x00FF);
            std::copy(S[slot].begin(), S[slot].end(), &addedShares[2]);
            OutgoingMessage sharingMessage(position->second.connectionID(), FinalRoundSecondSharing, DCNetwork_.nodeID(),
                                           addedShares);
            DCNetwork_.outbox().push(std::move(sharingMessage));
        }
    }
}

void UnsecuredFinalRound::resultComputation() {
    size_t numSlots = S.size();

    uint32_t remainingShares = numSlots * (k_ - 1);
    while (remainingShares > 0) {
        auto sharingBroadcast = DCNetwork_.inbox().pop();

        if (sharingBroadcast.msgType() == FinalRoundSecondSharing) {

            size_t slot = (sharingBroadcast.body()[0]) | sharingBroadcast.body()[1];

            for (uint32_t p = 0; p < 4 + static_cast<uint32_t>(slots_[slot]); p++)
                S[slot][p] ^= sharingBroadcast.body()[p+2];

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
}