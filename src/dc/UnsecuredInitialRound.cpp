#include <iomanip>
#include "UnsecuredInitialRound.h"

#include "DCNetwork.h"
#include "InitState.h"
#include "SecuredInitialRound.h"
#include "../datastruct/MessageType.h"
#include "UnsecuredFinalRound.h"


UnsecuredInitialRound::UnsecuredInitialRound(DCNetwork &DCNet) : DCNetwork_(DCNet), k_(DCNetwork_.k()) {
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

UnsecuredInitialRound::~UnsecuredInitialRound() {}

std::unique_ptr<DCState> UnsecuredInitialRound::executeTask() {
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

    size_t msgSize = 16 * k_;

    std::vector<uint8_t> slot(8);

    int slotIndex = -1;
    if (l > 0) {
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        slotIndex = PRNG.GenerateWord32(0, 2 * k_ - 1);

        // set the values in Big Endian format
        slot[4] = (r & 0xFF00) >> 8;
        slot[5] = (r & 0x00FF);
        slot[6] = (l & 0xFF00) >> 8;
        slot[7] = (l & 0x00FF);

        // Calculate the CRC
        CRC32_.Update(&slot[4], 4);
        CRC32_.Final(slot.data());
    }

    std::vector<std::vector<uint8_t>> shares(k_);
    shares[k_ - 1].resize(msgSize);

    if (slotIndex > -1)
        for (uint32_t p = 0; p < 8; p++)
            shares[k_ - 1][slotIndex * 8 + p] ^= slot[p];

    // fill the first slices of the first k-1 shares with random values
    // and subtract the values from the corresponding slices in the k-th share
    for (uint32_t share = 0; share < k_ - 1; share++) {
        shares[share].resize(msgSize);
        PRNG.GenerateBlock(shares[share].data(), msgSize);

        // XOR The value to the final slot
        for (uint32_t p = 0; p < msgSize; p++)
            shares[k_ - 1][p] ^= shares[share][p];
    }

    // store the own share in S
    S = shares[nodeIndex_];

    // logging
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    // generate and broadcast the commitments for the first round
    UnsecuredInitialRound::sharingPartOne(shares);

    // logging
    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    // collect and validate the shares
    UnsecuredInitialRound::sharingPartTwo();

    // logging
    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();


    // collect and validate the final shares
    UnsecuredInitialRound::resultComputation();

    // used for debugging only
    //UnsecuredInitialRound::printSlots(S);

    // prepare round two
    std::vector<uint16_t> slots;

    // determine the non-empty slots in the message vector
    // and calculate the index of the own slot if present
    int finalSlotIndex = -1;
    uint32_t invalidCRCs = 0;
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        uint16_t slotSize = (S[slot * 8 + 6] << 8) | S[slot * 8 + 7];
        if (slotSize > 0) {
            // verify the CRC
            CRC32_.Update(&S[slot * 8 + 4], 4);

            bool valid = CRC32_.Verify(&S[slot * 8]);

            if (!valid) {
                invalidCRCs++;
            } else {
                if(static_cast<uint32_t>(slotIndex) == slot)
                    finalSlotIndex = slots.size();
                // store the size of the slot
                slots.push_back(slotSize);
            }
        }
    }

    if(invalidCRCs > std::floor(k_/2)) {
        std::cout << "More than k/2 invalid CRCs detected." << std::endl;
        std::cout << "Switching to Proof of Fairness Protocol" << std::endl;
        return std::make_unique<SecuredInitialRound>(DCNetwork_);
    }

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

    if (finalSlotIndex > -1) {
        std::cout << "Node " << DCNetwork_.nodeID() << ": sending in slot " << std::dec << finalSlotIndex << std::endl << std::endl;
    }

    // if no member wants to send a message, return to the Ready state
    if (slots.size() == 0) {
        // TODO check
        //return std::make_unique<ReadyState>(DCNetwork_);
        std::cout << "No sender in this round" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return std::make_unique<UnsecuredInitialRound>(DCNetwork_);
    } else
        return std::make_unique<UnsecuredFinalRound>(DCNetwork_, finalSlotIndex, std::move(slots));
}

void UnsecuredInitialRound::sharingPartOne(std::vector<std::vector<uint8_t>> &shares) {
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), position);


        OutgoingMessage rsMessage(position->second.connectionID(), RoundOneSharingOne, DCNetwork_.nodeID(),
                                  shares[memberIndex]);
        DCNetwork_.outbox().push(std::move(rsMessage));
    }
}

void UnsecuredInitialRound::sharingPartTwo() {
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == RoundOneSharingOne) {
            for (uint32_t p = 0; p < 16 * k_; p++)
                S[p] ^= sharingMessage.body()[p];

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // broadcast the added shares
    // ensure that the messages arrive evenly distributed in time
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        OutgoingMessage sharingBroadcast(position->second.connectionID(), RoundOneSharingTwo, DCNetwork_.nodeID(),
                                         S);
        DCNetwork_.outbox().push(std::move(sharingBroadcast));
    }
}

void UnsecuredInitialRound::resultComputation() {
    // collect the added shares from the other k-1 members and validate them by adding the corresponding commitments
    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto sharingBroadcast = DCNetwork_.inbox().pop();

        if (sharingBroadcast.msgType() == RoundOneSharingTwo) {

            for (uint32_t p = 0; p < 16 * k_; p++)
                S[p] ^= sharingBroadcast.body()[p];

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
}