#include <iomanip>
#include "RoundOneUnsecured.h"

#include "DCNetwork.h"
#include "InitState.h"
#include "RoundOneSecured.h"
#include "ReadyState.h"
#include "FinalRound.h"
#include "../datastruct/MessageType.h"


RoundOneUnsecured::RoundOneUnsecured(DCNetwork &DCNet) : DCNetwork_(DCNet), k_(DCNetwork_.k()) {
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

RoundOneUnsecured::~RoundOneUnsecured() {}

std::unique_ptr<DCState> RoundOneUnsecured::executeTask() {
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

        // XOR The value to the last slot
        for (uint32_t p = 0; p < msgSize; p++)
            shares[k_ - 1][p] ^= shares[share][p];
    }

    // store the own share in S
    S = shares[nodeIndex_];

    // generate and broadcast the commitments for the first round
    RoundOneUnsecured::sharingPartOne(shares);

    // collect and validate the shares
    RoundOneUnsecured::sharingPartTwo();


    // collect and validate the final shares
    RoundOneUnsecured::resultComputation();

    RoundOneUnsecured::printSlots(S);

    // prepare round two
    std::vector<uint16_t> slots;

    // determine the non-empty slots in the message vector
    // and calculate the index of the own slot if present
    int finalSlotIndex = -1;
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        if (slotIndex == slot)
            finalSlotIndex = slots.size();

        uint16_t slotSize = (S[slot * 8 + 6] << 8) | S[slot * 8 + 7];
        if (slotSize > 0) {
            // verify the CRC
            CRC32_.Update(&S[slot * 8 + 4], 4);

            bool valid = CRC32_.Verify(&S[slot * 8]);

            if (!valid) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    std::cout << "Invalid CRC detected." << std::endl;
                    std::cout << "Restarting Round One." << std::endl;
                }
                return std::make_unique<RoundOneUnsecured>(DCNetwork_);
            }

            // store the size of the slot along with the seed
            slots.push_back(slotSize);
        }
    }

    // if no member wants to send a message, return to the Ready state
    if (slots.size() == 0)
        return std::make_unique<ReadyState>(DCNetwork_);
    else
        return std::make_unique<FinalRound>(DCNetwork_, finalSlotIndex, std::move(slots));
}

void RoundOneUnsecured::sharingPartOne(std::vector<std::vector<uint8_t>> &shares) {
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), position);


        OutgoingMessage rsMessage(position->second.connectionID(), RoundOneSharingPartOne, DCNetwork_.nodeID(),
                                  shares[memberIndex]);
        DCNetwork_.outbox().push(std::move(rsMessage));
    }
}

void RoundOneUnsecured::sharingPartTwo() {
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == RoundOneSharingPartOne) {
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

        OutgoingMessage sharingBroadcast(position->second.connectionID(), RoundOneSharingPartTwo, DCNetwork_.nodeID(), S);
        DCNetwork_.outbox().push(std::move(sharingBroadcast));
    }
}

void RoundOneUnsecured::resultComputation() {
    // collect the added shares from the other k-1 members and validate them by adding the corresponding commitments
    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto sharingBroadcast = DCNetwork_.inbox().pop();

        if (sharingBroadcast.msgType() == RoundOneSharingPartTwo) {
            uint32_t memberIndex = std::distance(DCNetwork_.members().begin(),
                                                 DCNetwork_.members().find(sharingBroadcast.senderID()));

            for (uint32_t p = 0; p < 16 * k_; p++)
                S[p] ^= sharingBroadcast.body()[p];

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
}

void RoundOneUnsecured::printSlots(std::vector<uint8_t> &slots) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << std::dec << "Node: " << DCNetwork_.nodeID() << std::endl;
    std::cout << "| ";
    for (int slot = 0; slot < 2 * k_; slot++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot* 8];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot* 8 + 1];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot* 8 + 2];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot* 8 + 3];
        std::cout << " ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot* 8 + 4];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot* 8 + 5];
        std::cout << " ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot* 8 + 6];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) slots[slot* 8 + 7];
        std::cout << " | ";
    }
    std::cout << std::endl << std::endl;
}