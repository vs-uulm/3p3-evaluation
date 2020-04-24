#include <numeric>
#include <cryptopp/oids.h>
#include "FairnessProtocol.h"
#include "ReadyState.h"
#include "../datastruct/MessageType.h"
#include "SecuredInitialRound.h"
#include "InitState.h"

ProofOfFairness::ProofOfFairness(DCNetwork &DCNet, size_t slotIndex, std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues,
                                 std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()), slotIndex_(slotIndex), rValues_(std::move(rValues)),
          commitments_(std::move(commitments)) {

    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

ProofOfFairness::~ProofOfFairness() {}

std::unique_ptr<DCState> ProofOfFairness::executeTask() {
    ProofOfFairness::coinFlip();

    // TODO undo
    outcome_ = OpenCommitments;

    ProofOfFairness::openCommitments();

    int result = ProofOfFairness::validateProof();
    if(result < 0) {
        std::cout << "Result less than 0" << std::endl;
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Proof of fairness finished" << std::endl;
    }
    return std::make_unique<ReadyState>(DCNetwork_);
}

int ProofOfFairness::coinFlip() {
    size_t slotSize = 8 + 33 * k_;
    size_t numSlices = std::ceil(slotSize / 31.0);
    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

    std::vector<std::vector<CryptoPP::ECPPoint>> sumC_(2 * k_);
    rho_.resize(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        sumC_[slot].resize(numSlices);
        rho_[slot].reserve(numSlices);

        for (uint32_t slice = 0; slice < numSlices; slice++) {
            // generate a random value r' for each slice
            CryptoPP::Integer r_(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            // add r' to rho'
            rho_[slot].push_back(r_);
            // add the commitment and random value r of each share of each slice
            for (uint32_t share = 0; share < k_; share++) {
                sumC_[slot][slice] = curve_.GetCurve().Add(sumC_[slot][slice],
                                                          commitments_[DCNetwork_.nodeID()][slot][share][slice]);
                rho_[slot][slice] += rValues_[slot][share][slice];
            }

            CryptoPP::ECPPoint r_G = curve_.GetCurve().ScalarMultiply(G, r_);
            sumC_[slot][slice] = curve_.GetCurve().Add(sumC_[slot][slice], r_G);
            rho_[slot][slice] = rho_[slot][slice].Modulo(curve_.GetSubgroupOrder());
        }
    }

    // create a random slot permutation
    permutation_.resize(2 * k_);
    std::iota(permutation_.begin(), permutation_.end(), 0);
    PRNG.Shuffle(permutation_.begin(), permutation_.end());

    std::vector<std::vector<uint8_t>> encodedCommitments;
    encodedCommitments.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<uint8_t> commitmentVector(numSlices * encodedPointSize);
        for (uint32_t slice = 0, offset = 0; slice < numSlices; slice++, offset += encodedPointSize)
            curve_.GetCurve().EncodePoint(&commitmentVector[offset], sumC_[permutation_[slot]][slice], true);

        encodedCommitments.push_back(std::move(commitmentVector));
    }

    newCommitments_.reserve(k_);
    newCommitments_.insert(std::pair(DCNetwork_.nodeID(), std::move(sumC_)));

    // broadcast the commitments
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2 * k_; slot++) {
            OutgoingMessage commitBroadcast(position->second.connectionID(), ZeroKnowledgeCommitments,
                                            DCNetwork_.nodeID(), encodedCommitments[slot]);
            DCNetwork_.outbox().push(std::move(commitBroadcast));
        }
    }


    // collect the commitments from the other parties
    // prepare the commitment storage
    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        std::vector<std::vector<CryptoPP::ECPPoint>> commitmentMatrix;
        commitmentMatrix.reserve(2 * k_);

        newCommitments_.insert(std::pair(member->second.nodeID(), std::move(commitmentMatrix)));
    }

    // collect the commitments from the other k-1 members
    uint32_t remainingCommitments = 2 * k_ * (k_ - 1);
    while (remainingCommitments > 0) {
        auto commitBroadcast = DCNetwork_.inbox().pop();

        if (commitBroadcast.msgType() == ZeroKnowledgeCommitments) {

            std::vector<CryptoPP::ECPPoint> commitmentVector;
            commitmentVector.reserve(numSlices);

            for (uint32_t slice = 0, offset = 0; slice < numSlices; slice++, offset += encodedPointSize) {
                CryptoPP::ECPPoint commitment;
                curve_.GetCurve().DecodePoint(commitment, &commitBroadcast.body()[offset],
                                              encodedPointSize);

                commitmentVector.push_back(std::move(commitment));
            }
            newCommitments_[commitBroadcast.senderID()].push_back(std::move(commitmentVector));

            remainingCommitments--;
        } else {
            DCNetwork_.inbox().push(commitBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    return 0;
}

void ProofOfFairness::openCommitments() {
    size_t slotSize = 8 + 33 * k_;
    size_t numSlices = std::ceil(slotSize / 31.0);

    // create pairs (slot, r')
    std::vector<std::vector<uint8_t>> encodedRhoMatrix;
    encodedRhoMatrix.reserve(2*k_-1);

    for(uint32_t slot = 0; slot < 2*k_; slot++) {
        if(permutation_[slot] != slotIndex_) {
            std::vector<uint8_t> encodedRhoVector(2 + 32 * numSlices);
            encodedRhoVector[0] = (slot & 0xFF00) >> 8;
            encodedRhoVector[1] = (slot & 0x00FF);

            for(uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 32)
                rho_[permutation_[slot]][slice].Encode(&encodedRhoVector[offset], 32);

            encodedRhoMatrix.push_back(std::move(encodedRhoVector));
        }
    }

    // broadcast the proof
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2*k_ - 1; slot++) {
            OutgoingMessage commitBroadcast(position->second.connectionID(), ZeroKnowledgeProof,
                                            DCNetwork_.nodeID(), encodedRhoMatrix[slot]);
            DCNetwork_.outbox().push(std::move(commitBroadcast));
        }
    }
}

void ProofOfFairness::proofKnowledge() {

}

int ProofOfFairness::validateProof() {
    size_t slotSize = 8 + 33 * k_;
    size_t numSlices = std::ceil(slotSize / 31.0);

    /*
    for(auto& member : DCNetwork_.members()) {
        std::vector<bool> validatedSlots(2*k_ -1);
        for(uint32_t slot = 0; slot < 2*k_-1; slot++) {
            validatedSlots[slot] = false;
        }
        validatedSlots_.insert(std::pair(member.second.nodeID(), std::move(validatedSlots)));
    } */
    // TODO make this more robust against misbehaving members
    int remainingValidations = (k_-1)*(2*k_-1);
    // collect messages until all members are validated
    while (remainingValidations > 0) {
        auto receivedMessage = DCNetwork_.inbox().pop();

        if (receivedMessage.msgType() == ZeroKnowledgeProof) {
            if(outcome_ == OpenCommitments) {
                uint32_t slot = (receivedMessage.body()[0] << 8) | receivedMessage.body()[1];

                for(uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 32) {
                    CryptoPP::Integer rho(&receivedMessage.body()[offset], 32);
                    CryptoPP::Integer s(CryptoPP::Integer::Zero());
                    CryptoPP::ECPPoint commitment = commit(rho, s);

                    // validate the commitment
                    if((newCommitments_[receivedMessage.senderID()][slot][slice].x != commitment.x)
                      || (newCommitments_[receivedMessage.senderID()][slot][slice].y != commitment.y)) {
                        std::cout << "Proof of fairness: invalid commitment detected" << std::endl;
                        DCNetwork_.members().erase(receivedMessage.senderID());
                        return -1;
                    }
                }
                remainingValidations--;
            } else {

            }
        } else {
            DCNetwork_.inbox().push(receivedMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    return 0;
}

inline CryptoPP::ECPPoint ProofOfFairness::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve_.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = curve_.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = curve_.GetCurve().Add(rG, sH);
    return commitment;
}