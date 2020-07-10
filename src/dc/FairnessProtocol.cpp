#include <numeric>
#include <cryptopp/oids.h>
#include <iomanip>
#include "FairnessProtocol.h"
#include "ReadyState.h"
#include "../datastruct/MessageType.h"
#include "SecuredInitialRound.h"
#include "InitState.h"

std::mutex cout_mutex1;

FairnessProtocol::FairnessProtocol(DCNetwork &DCNet, size_t numSlices, size_t slotIndex,
                                 std::vector<std::vector<std::vector<CryptoPP::Integer>>> rValues,
                                 std::unordered_map<uint32_t, std::vector<std::vector<std::vector<CryptoPP::ECPPoint>>>> commitments)
        : DCNetwork_(DCNet), k_(DCNetwork_.k()), numSlices_(numSlices), slotIndex_(slotIndex), rValues_(std::move(rValues)),
          commitments_(std::move(commitments)) {

    curve_.Initialize(CryptoPP::ASN1::secp256k1());

    // determine the index of the own nodeID in the ordered member list
    nodeIndex_ = std::distance(DCNetwork_.members().begin(), DCNetwork_.members().find(DCNetwork_.nodeID()));
}

FairnessProtocol::~FairnessProtocol() {}

std::unique_ptr<DCState> FairnessProtocol::executeTask() {
    std::vector<double> runtimes;
    auto start = std::chrono::high_resolution_clock::now();

    FairnessProtocol::distributeCommitments();

    // logging
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    int result = FairnessProtocol::coinFlip();
    if (result < 0) {
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    // logging
    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    runtimes.push_back(elapsed.count());
    start = std::chrono::high_resolution_clock::now();

    if(outcome_ == OpenCommitments)
        result = FairnessProtocol::openCommitments();
    else
        result = FairnessProtocol::proofKnowledge();

    if (result < 0) {
        // TODO clean up the inbox
        return std::make_unique<InitState>(DCNetwork_);
    }

    // Logging
    if (DCNetwork_.logging()) {
        auto finish = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = finish - start;
        double duration = elapsed.count();

        std::vector<uint8_t> log(3 * sizeof(double) + 1);
        // runtimes
        std::memcpy(&log[0], &runtimes[0], sizeof(double));
        std::memcpy(&log[8], &runtimes[1], sizeof(double));
        std::memcpy(&log[16], &duration, sizeof(double));
        // Outcome
        log[3 * sizeof(double)] = (outcome_ == OpenCommitments) ? 0 : 1;

        OutgoingMessage logMessage(CENTRAL, FairnessLoggingMessage, DCNetwork_.nodeID(), std::move(log));
        DCNetwork_.outbox().push(std::move(logMessage));
    }


    if(DCNetwork_.securityLevel() == Secured)
        return std::make_unique<ReadyState>(DCNetwork_);
    else
        return std::make_unique<FairnessProtocol>(DCNetwork_, numSlices_, slotIndex_, rValues_, commitments_);
}

int FairnessProtocol::coinFlip() {
    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

    std::vector<CryptoPP::Integer> shares(k_);
    std::vector<CryptoPP::Integer> rValues;
    std::vector<CryptoPP::ECPPoint> commitments;
    rValues.reserve(k_);
    commitments.reserve(k_);

    //create the first k-1 shares and the commitments for the coin flip
    for(uint32_t share = 0; share < k_; share++) {
        CryptoPP::Integer s(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
        CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
        CryptoPP::ECPPoint C = commit(r,s);
        rValues.push_back(std::move(r));
        commitments.push_back(std::move(C));
        shares[share] = std::move(s);
    }

    // store the own share
    CryptoPP::Integer S = shares[nodeIndex_];
    CryptoPP::Integer R = rValues[nodeIndex_];

    // encode the commitments
    std::vector<uint8_t> encodedCommitments(k_ * encodedPointSize);
    for (uint32_t share = 0, offset = 0; share < k_; share++, offset += encodedPointSize)
        curve_.GetCurve().EncodePoint(&encodedCommitments[offset], commitments[share], true);

    // broadcast the commitments
    auto position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        OutgoingMessage commitBroadcast(position->second.connectionID(), ZeroKnowledgeCoinCommitments,
                                        DCNetwork_.nodeID(), encodedCommitments);
        DCNetwork_.outbox().push(std::move(commitBroadcast));
    }


    std::unordered_map<uint32_t, std::vector<CryptoPP::ECPPoint>> C;
    C.reserve(k_);
    C.insert(std::pair(DCNetwork_.nodeID(), std::move(commitments)));


    // collect the commitments from the other k-1 members
    uint32_t remainingCommitments = k_ - 1;
    while (remainingCommitments > 0) {
        auto commitBroadcast = DCNetwork_.inbox().pop();

        if (commitBroadcast.msgType() == ZeroKnowledgeCoinCommitments) {

            std::vector<CryptoPP::ECPPoint> commitmentVector;
            commitmentVector.reserve(k_);

            for (uint32_t share = 0, offset = 0; share < k_; share++, offset += encodedPointSize) {
                CryptoPP::ECPPoint commitment;
                curve_.GetCurve().DecodePoint(commitment, &commitBroadcast.body()[offset],
                                              encodedPointSize);

                commitmentVector.push_back(std::move(commitment));
            }
            C.insert(std::pair(commitBroadcast.senderID(), std::move(commitmentVector)));

            remainingCommitments--;
        } else {
            DCNetwork_.inbox().push(commitBroadcast);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // distribute the shares
    position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        uint32_t memberIndex = std::distance(DCNetwork_.members().begin(), position);

        std::vector<uint8_t> encodedShare(64);
        rValues[memberIndex].Encode(&encodedShare[0], 32);
        shares[memberIndex].Encode(&encodedShare[32],32);

        OutgoingMessage sharingMessage(position->second.connectionID(), ZeroKnowledgeCoinSharingOne,
                                        DCNetwork_.nodeID(), encodedShare);
        DCNetwork_.outbox().push(std::move(sharingMessage));
    }

    // collect the shares from the other k-1 members
    uint32_t remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == ZeroKnowledgeCoinSharingOne) {

            CryptoPP::Integer r(&sharingMessage.body()[0], 32);
            CryptoPP::Integer s(&sharingMessage.body()[32], 32);

            CryptoPP::ECPPoint commitment = commit(r,s);

            // validate the commitment
            if((C[sharingMessage.senderID()][nodeIndex_].x != commitment.x)
              || (C[sharingMessage.senderID()][nodeIndex_].y != commitment.y)) {
                std::cout << "Invalid commitment detected 1" << std::endl;
                return -1;
            }

            R += r;
            S += s;

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // reduce R and S
    R = R.Modulo(curve_.GetGroupOrder());
    S = S.Modulo(curve_.GetGroupOrder());

    std::vector<uint8_t> encodedShare(64);
    R.Encode(&encodedShare[0], 32);
    S.Encode(&encodedShare[32], 32);

    // distribute the added shares
    position = DCNetwork_.members().find(DCNetwork_.nodeID());
    for (uint32_t member = 0; member < k_ - 1; member++) {
        position++;
        if (position == DCNetwork_.members().end())
            position = DCNetwork_.members().begin();

        OutgoingMessage sharingMessage(position->second.connectionID(), ZeroKnowledgeCoinSharingTwo,
                                       DCNetwork_.nodeID(), encodedShare);
        DCNetwork_.outbox().push(std::move(sharingMessage));
    }

    remainingShares = k_ - 1;
    while (remainingShares > 0) {
        auto sharingMessage = DCNetwork_.inbox().pop();

        if (sharingMessage.msgType() == ZeroKnowledgeCoinSharingTwo) {

            CryptoPP::Integer r(&sharingMessage.body()[0], 32);
            CryptoPP::Integer s(&sharingMessage.body()[32], 32);

            CryptoPP::ECPPoint commitment = commit(r,s);

            // add the commitments
            CryptoPP::ECPPoint sumC;
            for(auto& c : C)
                sumC = curve_.GetCurve().Add(sumC, c.second[sharingMessage.senderID()]);

            // validate the commitment
            if((sumC.x != commitment.x) || (sumC.y != commitment.y)) {
                std::cout << "Invalid commitment detected 2" << std::endl;
                return -1;
            }

            R += r;
            S += s;

            remainingShares--;
        } else {
            DCNetwork_.inbox().push(sharingMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    S = S.Modulo(curve_.GetGroupOrder());

    if(S.IsEven())
        outcome_ = OpenCommitments;
    else
        outcome_ = ProofOfKnowledge;

    return 0;
}

void FairnessProtocol::distributeCommitments() {
    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

    std::vector<std::vector<CryptoPP::ECPPoint>> sumC_(2 * k_);
    rho_.resize(2 * k_);
    r_.resize(2 * k_);
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        sumC_[slot].resize(numSlices_);
        rho_[slot].reserve(numSlices_);
        r_[slot].reserve(numSlices_);

        for (uint32_t slice = 0; slice < numSlices_; slice++) {
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

            CryptoPP::ECPPoint r_G = curve_.GetCurve().Multiply(r_[slot][slice], G);
            sumC_[slot][slice] = curve_.GetCurve().Add(sumC_[slot][slice], r_G);
            rho_[slot][slice] = rho_[slot][slice].Modulo(curve_.GetGroupOrder());
        }
    }

    // create a random slot permutation
    permutation_.resize(2 * k_);
    std::iota(permutation_.begin(), permutation_.end(), 0);
    PRNG.Shuffle(permutation_.begin(), permutation_.end());

    std::vector<std::vector<uint8_t>> encodedCommitments;
    encodedCommitments.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<uint8_t> commitmentVector(numSlices_ * encodedPointSize);
        for (uint32_t slice = 0, offset = 0; slice < numSlices_; slice++, offset += encodedPointSize)
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
            commitmentVector.reserve(numSlices_);

            for (uint32_t slice = 0, offset = 0; slice < numSlices_; slice++, offset += encodedPointSize) {
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
}

int FairnessProtocol::openCommitments() {
    std::cout << "Opening commitments" << std::endl;

    // create pairs (slot, r')
    std::vector<std::vector<uint8_t>> encodedRhoMatrix;
    encodedRhoMatrix.reserve(2 * k_ - 1);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        if (permutation_[slot] != slotIndex_) {
            std::vector<uint8_t> encodedRhoVector(2 + 32 * numSlices_);
            encodedRhoVector[0] = (slot & 0xFF00) >> 8;
            encodedRhoVector[1] = (slot & 0x00FF);

            for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 32)
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

    int remainingValidations = (k_ - 1) * (2 * k_ - 1);
    // collect messages until all members are validated
    while (remainingValidations > 0) {
        auto receivedMessage = DCNetwork_.inbox().pop();

        if (receivedMessage.msgType() == ZeroKnowledgeOpenCommitments) {
            uint32_t slot = (receivedMessage.body()[0] << 8) | receivedMessage.body()[1];

            for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 32) {
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

int FairnessProtocol::proofKnowledge() {
    std::cout << "Proving knowledge" << std::endl;

    size_t encodedPointSize = curve_.GetCurve().EncodedPointSize(true);

    // generate sigmas
    std::vector<std::vector<CryptoPP::ECPPoint>> blindedSigmaMatrix;
    std::vector<std::vector<CryptoPP::Integer>> sigmaMatrix;
    blindedSigmaMatrix.reserve(2 * k_);
    sigmaMatrix.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<CryptoPP::ECPPoint> blindedSigmaVector;
        std::vector<CryptoPP::Integer> sigmaVector;
        blindedSigmaVector.reserve(numSlices_);
        sigmaVector.reserve(numSlices_);

        for (uint32_t slice = 0; slice < numSlices_; slice++) {
            CryptoPP::Integer sigma(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            CryptoPP::ECPPoint blindedSigma = curve_.GetCurve().Multiply(sigma, G);
            sigmaVector.push_back(std::move(sigma));
            blindedSigmaVector.push_back(std::move(blindedSigma));
        }
        sigmaMatrix.push_back(std::move(sigmaVector));
        blindedSigmaMatrix.push_back(std::move(blindedSigmaVector));
    }

    std::vector<std::vector<uint8_t>> encodedSigmas;
    encodedSigmas.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<uint8_t> sigmaVector(4 + numSlices_ * encodedPointSize);

        sigmaVector[0] = (slot & 0xFF00) >> 8;
        sigmaVector[1] = (slot & 0x00FF);
        sigmaVector[2] = (permutation_[slot] & 0xFF00) >> 8;
        sigmaVector[3] = (permutation_[slot] & 0x00FF);

        for (uint32_t slice = 0, offset = 4; slice < numSlices_; slice++, offset += encodedPointSize)
            curve_.GetCurve().EncodePoint(&sigmaVector[offset], blindedSigmaMatrix[slot][slice], true);

        encodedSigmas.push_back(std::move(sigmaVector));
    }

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
            sigmaVector.reserve(numSlices_);

            uint32_t slot = (sigmaBroadcast.body()[0] << 8) | sigmaBroadcast.body()[1];
            uint32_t permutation = (sigmaBroadcast.body()[2] << 8) | sigmaBroadcast.body()[3];
            slotMapping[sigmaBroadcast.senderID()][permutation] = slot;

            for (uint32_t slice = 0, offset = 4; slice < numSlices_; slice++, offset += encodedPointSize) {
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
    std::vector<std::vector<CryptoPP::Integer>> zMatrix(2*k_);
    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        zMatrix[slot].resize(numSlices_);

        for (uint32_t slice = 0; slice < numSlices_; slice++) {
            CryptoPP::Integer z(PRNG, CryptoPP::Integer::One(), curve_.GetMaxExponent());
            zMatrix[slot][slice] = std::move(z);
        }
    }

    std::vector<std::vector<uint8_t>> zEncoded;
    zEncoded.reserve(2 * k_);

    for (uint32_t slot = 0; slot < 2 * k_; slot++) {
        std::vector<uint8_t> zVector(2 + numSlices_ * 32);

        zVector[0] = (slot & 0xFF00) > 8;
        zVector[1] = (slot & 0x00FF);
        for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 32)
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
        std::vector<std::vector<CryptoPP::Integer>> zMatrix(2*k_);
        zStorage.insert(std::pair(member->second.nodeID(), std::move(zMatrix)));
    }

    remainingMessages = 2 * k_ * (k_ - 1);
    while (remainingMessages > 0) {
        auto zBroadcast = DCNetwork_.inbox().pop();

        if (zBroadcast.msgType() == ZeroKnowledgeSigmaResponse) {

            std::vector<CryptoPP::Integer> zVector;
            zVector.reserve(numSlices_);

            uint32_t slot = (zBroadcast.body()[0] << 8) | zBroadcast.body()[1];

            for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 32) {
                CryptoPP::Integer z(&zBroadcast.body()[offset], 32);
                zVector.push_back(std::move(z));
            }

            zStorage[zBroadcast.senderID()][slot] = std::move(zVector);

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
                wVector.reserve(numSlices_);

                for (uint32_t slice = 0; slice < numSlices_; slice++) {
                    CryptoPP::Integer w = r_[slot][slice] * zStorage[member->first][slot][slice] + sigmaMatrix[slot][slice];
                    w = w.Modulo(curve_.GetGroupOrder());
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
                std::vector<uint8_t> wVector(2 + numSlices_ * 32);

                wVector[0] = (slot & 0xFF00) >> 8;
                wVector[1] = (slot & 0x00FF);
                for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 32)
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
    uint32_t remainingValidations = 2 * k_ * (k_ - 1);
    while (remainingValidations > 0) {
        auto wBroadcast = DCNetwork_.inbox().pop();

        if (wBroadcast.msgType() == ZeroKnowledgeSigmaProof) {

            uint32_t slot = (wBroadcast.body()[0] << 8) | wBroadcast.body()[1];

            for (uint32_t slice = 0, offset = 2; slice < numSlices_; slice++, offset += 32) {
                CryptoPP::Integer w(&wBroadcast.body()[offset], 32);
                CryptoPP::ECPPoint wG = curve_.GetCurve().Multiply(w, G);

                // Add all the original commitments at this slice and the permutated slot
                CryptoPP::ECPPoint sumC;
                for (uint32_t share = 0; share < k_; share++) {
                    sumC = curve_.GetCurve().Add(sumC, commitments_[wBroadcast.senderID()][slot][share][slice]);
                }

                // Retrieve r'G by calculating C' + Inv(C) = C' - C = (r+r')G + xH - (rG + xH) = r'G
                CryptoPP::ECPPoint r_G = curve_.GetCurve().Add(
                        newCommitments_[wBroadcast.senderID()][slotMapping[wBroadcast.senderID()][slot]][slice],
                        curve_.GetCurve().Inverse(sumC));
                CryptoPP::ECPPoint zr_G = curve_.GetCurve().Multiply(zMatrix[slot][slice], r_G);

                CryptoPP::ECPPoint zr_GsigmaG = curve_.GetCurve().Add(zr_G,
                                                                      sigmaStorage[wBroadcast.senderID()][slot][slice]);

                // now validate that (z*r')G + sigmaG = wG
                if (((wG.x != zr_GsigmaG.x) || (wG.y != zr_GsigmaG.y))) {
                    std::cout << "Invalid Commitment detected" << std::endl;
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


inline CryptoPP::ECPPoint FairnessProtocol::commit(CryptoPP::Integer &r, CryptoPP::Integer &s) {
    CryptoPP::ECPPoint rG = curve_.GetCurve().Multiply(r, G);
    CryptoPP::ECPPoint sH = curve_.GetCurve().Multiply(s, H);
    CryptoPP::ECPPoint commitment = curve_.GetCurve().Add(rG, sH);
    return commitment;
}