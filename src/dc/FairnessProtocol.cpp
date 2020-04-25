#include <numeric>
#include <cryptopp/oids.h>
#include "FairnessProtocol.h"
#include "ReadyState.h"
#include "../datastruct/MessageType.h"
#include "SecuredInitialRound.h"
#include "InitState.h"

ProofOfFairness::ProofOfFairness(DCNetwork &DCNet, size_t slotIndex,
                                 std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues,
                                 std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()), slotIndex_(slotIndex), rValues_(std::move(rValues)),
          commitments_(std::move(commitments)) {

    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

ProofOfFairness::~ProofOfFairness() {}

std::unique_ptr<DCState> ProofOfFairness::executeTask() {
    // TODO undo
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    outcome_ = ProofOfKnowledge;
    //outcome_ = OpenCommitments;

    // TODO add more general parameters like numSlots and numSlices
    ProofOfFairness::coinFlip();

    int result;
    if(outcome_ == OpenCommitments)
        result = ProofOfFairness::openCommitments();
    else
        result = ProofOfFairness::proofKnowledge();

    if (result < 0) {
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "Proof of fairness finished" << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(60));
    return std::make_unique<ReadyState>(DCNetwork_);
}

int ProofOfFairness::coinFlip() {
    size_t slotSize = 8 + 33 * k_;
    size_t numSlices = std::ceil(slotSize / 31.0);
    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

    std::vector<std::vector<CryptoPP::ECPPoint>> sumC_(2 * k_);
    rho_.resize(2 * k_);
    r_.resize(2 * k_);
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        sumC_[slot].resize(numSlices);
        rho_[slot].reserve(numSlices);
        r_[slot].reserve(numSlices);

        for (uint32_t slice = 0; slice < numSlices; slice++) {
            // generate a random value r' for each slice
            CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            // add r' to rho'
            rho_[slot].push_back(r);

            // store r'
            r_[slot].push_back(std::move(r));

            // add the commitment and random value r of each share of each slice
            for (uint32_t share = 0; share < k_; share++) {
                sumC_[slot][slice] = curve_.GetCurve().Add(sumC_[slot][slice],
                                                           commitments_[DCNetwork_.nodeID()][slot][share][slice]);
                rho_[slot][slice] += rValues_[slot][share][slice];
            }

            CryptoPP::ECPPoint r_G = curve_.GetCurve().ScalarMultiply(G, r_[slot][slice]);
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

int ProofOfFairness::openCommitments() {
    size_t slotSize = 8 + 33 * k_;
    size_t numSlices = std::ceil(slotSize / 31.0);

    // create pairs (slot, r')
    std::vector<std::vector<uint8_t>> encodedRhoMatrix;
    encodedRhoMatrix.reserve(2 * k_ - 1);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        if (permutation_[slot] != slotIndex_) {
            std::vector<uint8_t> encodedRhoVector(2 + 32 * numSlices);
            encodedRhoVector[0] = (slot & 0xFF00) >> 8;
            encodedRhoVector[1] = (slot & 0x00FF);

            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 32)
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

        for (uint32_t slot = 0; slot < 2 * k_ - 1; slot++) {
            OutgoingMessage commitBroadcast(position->second.connectionID(), ZeroKnowledgeOpenCommitments,
                                            DCNetwork_.nodeID(), encodedRhoMatrix[slot]);
            DCNetwork_.outbox().push(std::move(commitBroadcast));
        }
    }

    // TODO make this more robust against misbehaving members
    int remainingValidations = (k_ - 1) * (2 * k_ - 1);
    // collect messages until all members are validated
    while (remainingValidations > 0) {
        auto receivedMessage = DCNetwork_.inbox().pop();

        if (receivedMessage.msgType() == ZeroKnowledgeOpenCommitments) {
            uint32_t slot = (receivedMessage.body()[0] << 8) | receivedMessage.body()[1];

            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 32) {
                CryptoPP::Integer rho(&receivedMessage.body()[offset], 32);
                CryptoPP::Integer s(CryptoPP::Integer::Zero());
                CryptoPP::ECPPoint commitment = commit(rho, s);

                // validate the commitment
                if ((newCommitments_[receivedMessage.senderID()][slot][slice].x != commitment.x)
                    || (newCommitments_[receivedMessage.senderID()][slot][slice].y != commitment.y)) {
                    std::cout << "Proof of fairness: invalid commitment detected" << std::endl;
                    DCNetwork_.members().erase(receivedMessage.senderID());
                    return -1;
                }
            }
            remainingValidations--;
        } else {
            DCNetwork_.inbox().push(receivedMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    return 0;

}

int ProofOfFairness::proofKnowledge() {
    size_t slotSize = 8 + 33 * k_;
    size_t numSlices = std::ceil(slotSize / 31.0);
    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

    // generate sigmas
    std::vector<std::vector<CryptoPP::ECPPoint>> blindedSigmaMatrix;
    std::vector<std::vector<CryptoPP::Integer>> sigmaMatrix;
    blindedSigmaMatrix.reserve(2 * k_);
    sigmaMatrix.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<CryptoPP::ECPPoint> blindedSigmaVector;
        std::vector<CryptoPP::Integer> sigmaVector;
        blindedSigmaVector.reserve(numSlices);
        sigmaVector.reserve(numSlices);

        for (uint32_t slice = 0; slice < numSlices; slice++) {
            CryptoPP::Integer sigma(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            CryptoPP::ECPPoint blindedSigma = curve_.GetCurve().ScalarMultiply(G, sigma);
            sigmaVector.push_back(std::move(sigma));
            blindedSigmaVector.push_back(std::move(blindedSigma));
        }
        sigmaMatrix.push_back(std::move(sigmaVector));
        blindedSigmaMatrix.push_back(std::move(blindedSigmaVector));
    }

    std::vector<std::vector<uint8_t>> encodedSigmas;
    encodedSigmas.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<uint8_t> sigmaVector(4 + numSlices * encodedPointSize);

        sigmaVector[0] = (slot & 0xFF00) >> 8;
        sigmaVector[1] = (slot & 0x00FF);
        sigmaVector[2] = (permutation_[slot] & 0xFF00) >> 8;
        sigmaVector[3] = (permutation_[slot] & 0x00FF);

        for (uint32_t slice = 0, offset = 4; slice < numSlices; slice++, offset += encodedPointSize)
            curve_.GetCurve().EncodePoint(&sigmaVector[offset], blindedSigmaMatrix[slot][slice], true);

        encodedSigmas.push_back(std::move(sigmaVector));
    }

    // TODO combine this with encoding process
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2 * k_; slot++) {
            OutgoingMessage sigmaBroadcast(position->second.connectionID(), ZeroKnowledgeSigmaExchange,
                                           DCNetwork_.nodeID(), encodedSigmas[slot]);
            DCNetwork_.outbox().push(std::move(sigmaBroadcast));
        }
    }

    std::unordered_map<uint32_t, std::vector<uint32_t>> slotMapping;
    slotMapping.reserve(k_ - 1);

    std::unordered_map<uint32_t, std::vector<std::vector<CryptoPP::ECPPoint>>> sigmaStorage;
    sigmaStorage.reserve(k_ - 1);

    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        std::vector<uint32_t> slots(2 * k_);
        slotMapping.insert(std::pair(member->second.nodeID(), std::move(slots)));

        std::vector<std::vector<CryptoPP::ECPPoint>> sigmaMatrix;
        sigmaMatrix.reserve(2 * k_);
        sigmaStorage.insert(std::pair(member->second.nodeID(), std::move(sigmaMatrix)));
    }


    uint32_t remainingMessages = 2 * k_ * (k_ - 1);
    while (remainingMessages > 0) {
        auto sigmaBroadcast = DCNetwork_.inbox().pop();

        if (sigmaBroadcast.msgType() == ZeroKnowledgeSigmaExchange) {

            std::vector<CryptoPP::ECPPoint> sigmaVector;
            sigmaVector.reserve(numSlices);

            uint32_t slot = (sigmaBroadcast.body()[0] << 8) | sigmaBroadcast.body()[1];
            uint32_t permutation = (sigmaBroadcast.body()[2] << 8) | sigmaBroadcast.body()[3];
            slotMapping[sigmaBroadcast.senderID()][permutation] = slot;

            for (uint32_t slice = 0, offset = 4; slice < numSlices; slice++, offset += encodedPointSize) {
                CryptoPP::ECPPoint blindedSigma;
                curve_.GetCurve().DecodePoint(blindedSigma, &sigmaBroadcast.body()[offset],
                                              encodedPointSize);

                sigmaVector.push_back(std::move(blindedSigma));
            }
            sigmaStorage[sigmaBroadcast.senderID()].push_back(std::move(sigmaVector));

            remainingMessages--;
        } else {
            DCNetwork_.inbox().push(sigmaBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // generate z values
    std::vector<std::vector<CryptoPP::Integer>> zMatrix;
    zMatrix.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<CryptoPP::Integer> zVector;
        zVector.reserve(numSlices);

        for (uint32_t slice = 0; slice < numSlices; slice++) {
            CryptoPP::Integer z(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            zVector.push_back(std::move(z));
        }
        zMatrix.push_back(std::move(zVector));
    }

    std::vector<std::vector<uint8_t>> zEncoded;
    zEncoded.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<uint8_t> zVector(numSlices * 32);

        for (uint32_t slice = 0, offset = 0; slice < numSlices; slice++, offset += 32)
            zMatrix[slot][slice].Encode(&zVector[offset], 32);

        zEncoded.push_back(std::move(zVector));
    }

    // distribute the z values
    position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2 * k_; slot++) {
            OutgoingMessage zBroadcast(position->second.connectionID(), ZeroKnowledgeSigmaResponse,
                                       DCNetwork_.nodeID(), zEncoded[slot]);
            DCNetwork_.outbox().push(std::move(zBroadcast));
        }
    }

    std::unordered_map<uint32_t, std::vector<std::vector<CryptoPP::Integer>>> zStorage;
    zStorage.reserve(k_);

    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        std::vector<std::vector<CryptoPP::Integer>> zMatrix;
        zMatrix.reserve(2 * k_);
        zStorage.insert(std::pair(member->second.nodeID(), std::move(zMatrix)));
    }

    remainingMessages = 2 * k_ * (k_ - 1);
    while (remainingMessages > 0) {
        auto zBroadcast = DCNetwork_.inbox().pop();

        if (zBroadcast.msgType() == ZeroKnowledgeSigmaResponse) {

            std::vector<CryptoPP::Integer> zVector;
            zVector.reserve(numSlices);

            for (uint32_t slice = 0, offset = 0; slice < numSlices; slice++, offset += 32) {
                CryptoPP::Integer z(&zBroadcast.body()[offset], 32);
                zVector.push_back(std::move(z));
            }

            zStorage[zBroadcast.senderID()].push_back(std::move(zVector));

            remainingMessages--;
        } else {
            DCNetwork_.inbox().push(zBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // calculate the w values
    std::unordered_map<uint32_t, std::vector<std::vector<CryptoPP::Integer>>> wStorage;
    wStorage.reserve(k_ - 1);

    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        if (member->first != DCNetwork_.nodeID()) {
            std::vector<std::vector<CryptoPP::Integer>> wMatrix;
            wMatrix.reserve(2 * k_);
            for (uint32_t slot = 0; slot < 2 * k_; slot++) {
                std::vector<CryptoPP::Integer> wVector;
                wVector.reserve(numSlices);

                for (uint32_t slice = 0; slice < numSlices; slice++) {
                    CryptoPP::Integer w =
                            r_[slot][slice] * zStorage[member->first][slot][slice] + sigmaMatrix[slot][slice];
                    w = w.Modulo(curve_.GetSubgroupOrder());
                    wVector.push_back(std::move(w));
                }
                wMatrix.push_back(std::move(wVector));
            }
            wStorage.insert(std::pair(member->first, std::move(wMatrix)));
        }
    }

    std::unordered_map<uint32_t, std::vector<std::vector<uint8_t>>> wEncoded;
    wEncoded.reserve(k_-1);

    for (auto member = DCNetwork_.members().begin(); member != DCNetwork_.members().end(); member++) {
        if (member->first != DCNetwork_.nodeID()) {
            std::vector<std::vector<uint8_t>> wMatrix;
            wMatrix.reserve(2 * k_);

            for (uint32_t slot = 0; slot < 2 * k_; slot++) {
                std::vector<uint8_t> wVector(2 + numSlices * 32);

                wVector[0] = (slot & 0xFF00) >> 8;
                wVector[1] = (slot & 0x00FF);
                for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 32)
                    wStorage[member->first][slot][slice].Encode(&wVector[offset], 32);

                wMatrix.push_back(std::move(wVector));
            }
            wEncoded.insert(std::pair(member->first, std::move(wMatrix)));
        }
    }

    // distribute the w values
    position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        for (uint32_t slot = 0; slot < 2 * k_; slot++) {
            OutgoingMessage wBroadcast(position->second.connectionID(), ZeroKnowledgeSigmaProof,
                                       DCNetwork_.nodeID(), wEncoded[position->first][slot]);
            DCNetwork_.outbox().push(std::move(wBroadcast));
        }
    }

    // collect the w values
    // TODO make this more robust
    uint32_t remainingValidations = 2 * k_ * (k_ - 1);
    while (remainingValidations > 0) {
        auto wBroadcast = DCNetwork_.inbox().pop();

        if (wBroadcast.msgType() == ZeroKnowledgeSigmaProof) {

            uint32_t slot = (wBroadcast.body()[0] << 8) | wBroadcast.body()[1];

            for (uint32_t slice = 0, offset = 2; slice < numSlices; slice++, offset += 32) {
                CryptoPP::Integer w(&wBroadcast.body()[offset], 32);
                CryptoPP::ECPPoint wG = curve_.GetCurve().ScalarMultiply(G, w);

                // Add all the original commitments at this slice and the permutatet slot
                CryptoPP::ECPPoint sumC;
                for (uint32_t share = 0; share < k_; share++) {
                    sumC = curve_.GetCurve().Add(sumC, commitments_[wBroadcast.senderID()][slot][share][slice]);
                }

                // Retrieve r'G by calculating C' + Inv(C) = C' - C = (r+r')G + xH - (rG + xH) = r'G
                CryptoPP::ECPPoint r_G = curve_.GetCurve().Add(
                        newCommitments_[wBroadcast.senderID()][slotMapping[wBroadcast.senderID()][slot]][slice],
                        curve_.GetCurve().Inverse(sumC));
                CryptoPP::ECPPoint zr_G = curve_.GetCurve().ScalarMultiply(r_G,
                                                                           zMatrix[slot][slice]);

                CryptoPP::ECPPoint zr_GsigmaG = curve_.GetCurve().Add(zr_G,
                                                                      sigmaStorage[wBroadcast.senderID()][slot][slice]);

                // now validate that (z*r')H + sigmaH = wH
                if (((wG.x != zr_GsigmaG.x) || (wG.y != zr_GsigmaG.y))) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    std::cout << "Invalid proof" << std::endl;
                    return -1;
                }
            }

            remainingValidations--;
        } else {
            DCNetwork_.inbox().push(wBroadcast);
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