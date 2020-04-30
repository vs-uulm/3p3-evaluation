#include <cryptopp/oids.h>
#include "BlameProtocol.h"
#include "FairnessProtocol.h"
#include "InitState.h"

BlameProtocol::BlameProtocol(DCNetwork &DCNet, std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> oldCommitments)
: DCNetwork_(DCNet), k_(DCNetwork_.k()), slotIndex_(-1) {
    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));

}

BlameProtocol::BlameProtocol(DCNetwork &DCNet, int slotIndex, uint16_t sliceIndex, uint32_t suspiciousMember, CryptoPP::Integer seedPrivateKey,
        std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> oldCommitments)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()), slotIndex_(slotIndex), sliceIndex_(sliceIndex), suspiciousMember_(suspiciousMember),
          seedPrivateKey_(seedPrivateKey), oldCommitments_(oldCommitments) {

}

BlameProtocol::~BlameProtocol() {}


std::unique_ptr<DCState> BlameProtocol::executeTask() {
    size_t slotSize = 44;
    size_t numSlices = std::ceil(slotSize / 31.0);

    std::vector<CryptoPP::Integer> messageSlices;

    int newSlotIndex;
    if (slotIndex_ > 0) {
        newSlotIndex = PRNG.GenerateWord32(0, 2*k_);

        std::vector<uint8_t> messageSlot(slotSize);

        // set the nodeID of the suspicious member
        messageSlot[4] = (suspiciousMember_ & 0xFF000000) >> 24;
        messageSlot[5] = (suspiciousMember_ & 0x00FF0000) >> 16;
        messageSlot[6] = (suspiciousMember_ & 0x0000FF00) >> 8;
        messageSlot[7] = (suspiciousMember_ & 0x000000FF);

        // Slot
        messageSlot[8] = (slotIndex_ & 0xFF00) >> 8;
        messageSlot[9] = (slotIndex_ & 0x00FF);

        // Slice
        messageSlot[10] = (sliceIndex_ & 0xFF00) >> 8;
        messageSlot[11] = (sliceIndex_ & 0x00FF);

        // Ephemeral private key, used to generate the seed
        seedPrivateKey_.Encode(&messageSlot[12], 32);

        // Calculate the CRC
        CRC32_.Update(&messageSlot[4], 40);
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
        if (static_cast<uint32_t>(newSlotIndex) == slot) {
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
    BlameProtocol::sharingPartOne(shares);

    // collect and validate the shares
    int result = BlameProtocol::sharingPartTwo();
    //std::cout << "Sharing part two finished" << std::endl;
    // a blame message has been received
    if (result < 0) {
        // TODO clean up the inbox
        return std::make_unique<FairnessProtocol>(DCNetwork_, newSlotIndex, rValues_, commitments_);
    }

    // collect and validate the final shares
    std::vector<std::vector<uint8_t>> finalMessageVector = BlameProtocol::resultComputation();
    // Check if the protocol's execution has been interrupted by a blame message
    if (finalMessageVector.size() == 0) {
        // a blame message indicates that a member may have been excluded from the group
        // therefore a transition to the init state is performed,
        // which will execute a group membership protocol
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    bool invalidCRC = false;
    uint32_t nonEmptySlots = 0;
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        // TODO check
        bool notEmpty = false;
        for(uint8_t c : finalMessageVector[slot])
            notEmpty |= c;

        if(notEmpty) {
            // verify the CRC
            CRC32_.Update(&finalMessageVector[slot][4], 40);
            if(!CRC32_.Verify(finalMessageVector[slot].data())) {
                invalidCRC = true;
            } else if(newSlotIndex != slot) {
                CryptoPP::Integer r(&finalMessageVector[slot][12], 32);

                // Decode the member
                uint32_t memberID = (finalMessageVector[slot][4] << 24) | (finalMessageVector[slot][5] << 16)
                                            | (finalMessageVector[slot][6] << 8) | finalMessageVector[slot][7];

                // slot
                uint32_t slotIndex = (finalMessageVector[slot][8] << 8) | finalMessageVector[slot][9];

                // slice
                uint32_t sliceIndex = (finalMessageVector[slot][10] << 8) | finalMessageVector[slot][11];

                CryptoPP::Integer sharedSecret = curve_.GetCurve().ScalarMultiply(DCNetwork_.members().find(memberID)->second.publicKey(), r).x;

                std::array<uint8_t, 32> seed;
                sharedSecret.Encode(seed.data(), 32);

                DRNG.SetKeyWithIV(seed.data(), 16, seed.data() + 16, 16);


                uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(memberID));
                // verify that the commitment is indeed invalid

                CryptoPP::Integer R_;
                CryptoPP::ECPPoint C_;
                // skip to the rValue at this point
                for (uint32_t share = 0; share < k_; share++) {
                    for (uint32_t slice = 0; slice < numSlices; slice++) {
                        CryptoPP::Integer r(DRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
                        if(slice == sliceIndex)
                            R_ += r;
                    }
                    C_ = curve_.GetCurve().Add(C_, commitments_[memberIndex][slotIndex][share][sliceIndex]);
                }
                R_ = R_.Modulo(curve_.GetSubgroupOrder());

                CryptoPP::Integer S_(CryptoPP::Integer::Zero());
                CryptoPP::ECPPoint commitment = commit(R_, S_);

                // check if the commitment is invalid
                if ((C_.x != commitment.x) || (C_.y != commitment.y)) {
                    std::cout << "Suspicious Member removed" << std::endl;
                    DCNetwork_.members().erase(memberID);
                }
            }
            nonEmptySlots++;
        }
    }
    // Check if there have been more senders than slots
    if(nonEmptySlots > oldCommitments_[nodeIndex_].size()) {
        std::cout << "Jamming Node identified." << std::endl;
        std::cout << "Switching to the Fairness Protocol" << std::endl;
        return std::make_unique<FairnessProtocol>(DCNetwork_, newSlotIndex, std::move(rValues_), std::move(commitments_));
    }

    if(invalidCRC) {
        std::cout << "Invalid CRC detected." << std::endl;
        std::cout << "Restarting Blame Protocol." << std::endl;
        return std::make_unique<BlameProtocol>(DCNetwork_, slotIndex_, sliceIndex_, suspiciousMember_,
                                               std::move(seedPrivateKey_), std::move(commitments_));
    }

    return std::make_unique<InitState>(DCNetwork_);
}

void BlameProtocol::sharingPartOne(std::vector<std::vector<std::vector<CryptoPP::Integer>>>& shares) {

}

int BlameProtocol::sharingPartTwo() {
    return 0;
}

std::vector<std::vector<uint8_t>> BlameProtocol::resultComputation() {

}

CryptoPP::ECPPoint BlameProtocol::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve_.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = curve_.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = curve_.GetCurve().Add(rG, sH);
    return commitment;
}