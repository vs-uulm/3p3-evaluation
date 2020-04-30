#include <cryptopp/oids.h>
#include "BlameProtocol.h"
#include "FairnessProtocol.h"
#include "InitState.h"
#include "../datastruct/MessageType.h"

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

    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));

}

BlameProtocol::~BlameProtocol() {}


std::unique_ptr<DCState> BlameProtocol::executeTask() {
    size_t slotSize = 44;
    size_t numSlices = 2;

    std::vector<CryptoPP::Integer> messageSlices;

    int newSlotIndex;
    if (slotIndex_ > 0) {
        newSlotIndex = PRNG.GenerateWord32(0, 2*k_);

        std::vector<uint8_t> messageSlot(44);

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
    size_t numSlices = 2;

    rValues_.resize(2 * k_);
    C.resize(2 * k_);
    R.resize(2 * k_);

    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);
    std::vector<std::vector<uint8_t>> encodedCommitments(2 * k_);
    std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        rValues_[slot].resize(k_);
        R[slot].reserve(numSlices);
        C[slot].resize(numSlices);

        commitmentCube[slot].resize(k_);
        encodedCommitments[slot].resize(2 + k_ * numSlices * encodedPointSize);

        for (uint32_t share = 0, offset = 2; share < k_; share++) {
            rValues_[slot][share].reserve(numSlices);
            commitmentCube[slot][share].reserve(numSlices);

            // encode the current slot in the first two bytes
            encodedCommitments[slot][0] = (slot & 0xFF00) >> 8;
            encodedCommitments[slot][1] = slot & 0x00FF;
            for (uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {
                // generate the random value r for this slice of the share
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
                rValues_[slot][share].push_back(std::move(r));

                // generate the commitment for the j-th slice of the i-th share
                CryptoPP::ECPPoint commitment = commit(rValues_[slot][share][slice], shares[slot][share][slice]);

                // store the commitment
                commitmentCube[slot][share].push_back(std::move(commitment));

                // compress the commitment and store in the given position in the vector
                curve_.GetCurve().EncodePoint(&encodedCommitments[slot][offset], commitmentCube[slot][share][slice],
                                              true);

                // Add the commitment to the sum C
                C[slot][slice] = curve_.GetCurve().Add(C[slot][slice], commitmentCube[slot][share][slice]);
            }
        }
    }

    // store the commitment matrix
    commitments_.reserve(k_);
    commitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(commitmentCube)));

    // store the random values used for the Commitments of the own share

    // get the index of the own share by checking the position of the local nodeID in the member list
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        for (uint32_t slice = 0; slice < numSlices; slice++) {
            R[slot].push_back(rValues_[slot][nodeIndex_][slice]);
        }
    }

    // broadcast the commitments
    // ensure that the messages arrive evenly distributed in time
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2 * k_; slot++) {
            OutgoingMessage commitBroadcast(position->second.connectionID(), BlameProtocolCommitments,
                                            DCNetwork_.nodeID(), encodedCommitments[slot]);
            DCNetwork_.outbox().push(std::move(commitBroadcast));
        }
    }

    // prepare the commitment storage
    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>> commitmentCube;
        commitmentCube.reserve(2 * k_);

        commitments_.insert(std::pair(member->second.nodeID(), std::move(commitmentCube)));
    }

    // collect the commitments from the other k-1 members
    uint32_t remainingCommitments = 2 * k_ * (k_ - 1);
    while (remainingCommitments > 0) {
        auto commitBroadcast = DCNetwork_.inbox().pop();

        if (commitBroadcast.msgType() == BlameProtocolCommitments) {

            std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
            commitmentMatrix.reserve(k_);

            // decode the slot and the share
            uint32_t slot = (commitBroadcast.body()[0] << 8) | (commitBroadcast.body()[1]);

            for (uint32_t share = 0, offset = 2; share < k_; share++) {
                std::vector<CryptoPP::ECPPoint> commitmentVector;
                commitmentVector.reserve(numSlices);

                for (uint32_t slice = 0; slice < numSlices; slice++, offset += encodedPointSize) {
                    CryptoPP::ECPPoint commitment;
                    curve_.GetCurve().DecodePoint(commitment, &commitBroadcast.body()[offset],
                                                  encodedPointSize);

                    C[slot][slice] = curve_.GetCurve().Add(C[slot][slice], commitment);
                    commitmentVector.push_back(std::move(commitment));
                }
                commitmentMatrix.push_back(std::move(commitmentVector));
            }
            commitments_[commitBroadcast.senderID()].push_back(std::move(commitmentMatrix));

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

            OutgoingMessage rsMessage(position->second.connectionID(), BlameProtocolSharingOne, DCNetwork_.nodeID(),
                                      sharingMessage);
            DCNetwork_.outbox().push(std::move(rsMessage));
        }
    }
}

int BlameProtocol::sharingPartTwo() {
    size_t numSlices = 2;
    // collect the shares from the other k-1 members and validate them using the broadcasted commitments
    uint32_t remainingShares = 2 * k_ * (k_ - 1);
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == BlameProtocolSharingOne) {

            uint32_t slot = (sharingMessage.body()[0] << 8) | sharingMessage.body()[1];

            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 64) {
                CryptoPP::Integer r(&sharingMessage.body()[offset], 32);
                CryptoPP::Integer s(&sharingMessage.body()[offset + 32], 32);

                // verify that the corresponding commitment is valid
                CryptoPP::ECPPoint commitment = commit(r, s);
                // if the commitment is invalid, blame the sender
                if ((commitment.x != commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].x)
                    || (commitment.y != commitments_[sharingMessage.senderID()][slot][DCNetwork_.nodeID()][slice].y)) {

                    BlameProtocol::injectBlameMessage(sharingMessage.senderID(), slot, slice, r, s);
                    std::cout << "Invalid commitment detected 1" << std::endl;
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
            S[slot][slice] = S[slot][slice].Modulo(curve_.GetSubgroupOrder());
            R[slot][slice] = R[slot][slice].Modulo(curve_.GetSubgroupOrder());

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
            OutgoingMessage rsBroadcast(position->second.connectionID(), BlameProtocolSharingTwo, DCNetwork_.nodeID(),
                                        sharingBroadcast[slot]);
            DCNetwork_.outbox().push(std::move(rsBroadcast));
        }
    }

    return 0;
}

std::vector<std::vector<uint8_t>> BlameProtocol::resultComputation() {
    size_t numSlices = 2;
    // collect the added shares from the other k-1 members and validate them by adding the corresponding commitments
    uint32_t remainingShares = 2 * k_ * (k_ - 1);
    while (remainingShares > 0) {
        auto rsBroadcast = DCNetwork_.inbox().pop();

        if (rsBroadcast.msgType() == BlameProtocolSharingTwo) {
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
                    BlameProtocol::injectBlameMessage(rsBroadcast.senderID(), slot, slice, R_, S_);
                    return std::vector<std::vector<uint8_t>>();
                }
                R[slot][slice] += R_;
                S[slot][slice] += S_;
            }

            remainingShares--;
        } else if (rsBroadcast.msgType() == BlameMessage) {
            BlameProtocol::handleBlameMessage(rsBroadcast);
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
            R[slot][slice] = R[slot][slice].Modulo(curve_.GetSubgroupOrder());
            S[slot][slice] = S[slot][slice].Modulo(curve_.GetSubgroupOrder());

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

void BlameProtocol::injectBlameMessage(uint32_t suspectID, uint32_t slot, uint32_t slice, CryptoPP::Integer &r, CryptoPP::Integer &s) {
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

void BlameProtocol::handleBlameMessage(ReceivedMessage &blameMessage) {
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

CryptoPP::ECPPoint BlameProtocol::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve_.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = curve_.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = curve_.GetCurve().Add(rG, sH);
    return commitment;
}