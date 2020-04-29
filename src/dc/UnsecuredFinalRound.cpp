#include <iomanip>
#include "UnsecuredFinalRound.h"
#include "DCNetwork.h"
#include "ReadyState.h"
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

        if (static_cast<uint32_t>(slotIndex_) == slot)
            shares[slot][k_ - 1] = submittedMessage;
        else
            shares[slot][k_ - 1].resize(slots_[slot]);

        for (uint32_t share = 0; share < k_ - 1; share++) {
            shares[slot][share].resize(slots_[slot]);
            PRNG.GenerateBlock(shares[slot][share].data(), slots_[slot]);

            // XOR The value to the final share
            for (uint32_t p = 0; p < slots_[slot]; p++)
                shares[slot][k_ - 1][p] ^= shares[slot][share][p];
        }

        S.push_back(shares[slot][nodeIndex_]);
    }


    UnsecuredFinalRound::sharingPartOne(shares);

    UnsecuredFinalRound::sharingPartTwo();

    UnsecuredFinalRound::resultComputation();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Node: " << std::dec << DCNetwork_.nodeID() << std::endl;
        for (auto &slot : S) {
            std::vector<uint8_t> msgHash = utils::sha256(slot);
            std::cout << "|";
            for (uint8_t c : msgHash) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
            }
            std::cout << "|" << std::endl;
        }
        std::cout << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
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
            std::vector<uint8_t> share(2 + slots_[slot]);
            share[0] = (slot & 0xFF00) >> 8;
            share[1] = (slot & 0x00FF);
            std::copy(shares[slot][memberIndex].begin(), shares[slot][memberIndex].end(), &share[2]);
            OutgoingMessage sharingMessage(position->second.connectionID(), RoundTwoSharingPartOne, DCNetwork_.nodeID(),
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

        if (sharingMessage.msgType() == RoundTwoSharingPartOne) {

            size_t slot = (sharingMessage.body()[0] << 8) | sharingMessage.body()[1];
            for (uint32_t p = 0; p < slots_[slot]; p++)
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
            std::vector<uint8_t> addedShares(2 + slots_[slot]);
            addedShares[0] = (slot & 0xFF00) >> 8;
            addedShares[1] = (slot & 0x00FF);
            std::copy(S[slot].begin(), S[slot].end(), &addedShares[2]);
            OutgoingMessage sharingMessage(position->second.connectionID(), RoundTwoSharingPartTwo, DCNetwork_.nodeID(),
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

        if (sharingBroadcast.msgType() == RoundTwoSharingPartTwo) {

            size_t slot = (sharingBroadcast.body()[0]) | sharingBroadcast.body()[1];

            for (uint32_t p = 0; p < slots_[slot]; p++)
                S[slot][p] ^= sharingBroadcast.body()[p+2];

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
}