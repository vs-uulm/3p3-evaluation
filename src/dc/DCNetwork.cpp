#include <cryptopp/oids.h>
#include "DCNetwork.h"
#include "InitState.h"

DCNetwork::DCNetwork(DCMember self, size_t k, SecurityLevel securityLevel, CryptoPP::Integer privateKey,
        uint32_t numThreads, std::unordered_map<uint32_t, Node>& neigbors, MessageQueue<ReceivedMessage>& inboxDC,
        MessageQueue<OutgoingMessage>& outboxThreePP, uint32_t interval, bool fullProtocol, bool logging,
        bool preparedCommitments)
: nodeID_(self.nodeID()), k_(k), securityLevel_(securityLevel), privateKey_(privateKey), numThreads_(numThreads), neighbors_(neigbors),
  inboxDC_(inboxDC), outboxThreePP_(outboxThreePP), state_(std::make_unique<InitState>(*this)),
  interval_(interval), fullProtocol_(fullProtocol), logging_(logging) {
    members_.insert(std::pair(nodeID_, self));

    if(preparedCommitments && (securityLevel_ == Secured))
        prepareCommitments();
}

void DCNetwork::run() {
    for(;;) {
        state_ = state_->executeTask();
    }
}

void DCNetwork::submitMessage(std::vector<uint8_t>& msg) {
    submittedMessages_.push(std::move(msg));
}

std::map<uint32_t, DCMember>& DCNetwork::members() {
    return members_;
}

std::unordered_map<uint32_t, Node>& DCNetwork::neighbors() {
    return neighbors_;
}

MessageQueue<ReceivedMessage>& DCNetwork::inbox() {
    return inboxDC_;
}

MessageQueue<OutgoingMessage>& DCNetwork::outbox() {
    return outboxThreePP_;
}

std::queue<std::vector<uint8_t>>& DCNetwork::submittedMessages() {
    return submittedMessages_;
}

uint32_t DCNetwork::nodeID() {
    return nodeID_;
}

size_t DCNetwork::k() {
    return k_;
}

uint32_t DCNetwork::numThreads() {
    return numThreads_;
}

CryptoPP::Integer& DCNetwork::privateKey() {
    return privateKey_;
}

SecurityLevel DCNetwork::securityLevel() {
    return securityLevel_;
}

uint32_t DCNetwork::interval() {
    return interval_;
}

bool DCNetwork::fullProtocol() {
    return fullProtocol_;
}

bool DCNetwork::logging() {
    return logging_;
}

void DCNetwork::prepareCommitments() {
    std::cout << "Preparing Commitments" << std::endl;
    CryptoPP::AutoSeededRandomPool PRNG;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    uint32_t numSlices = std::ceil((8 + 33 * k_) / 31.0);

    preparedCommitments_.resize(2*k_);
    for(uint32_t slot = 0; slot < 2*k_; slot++) {
        preparedCommitments_[slot].resize(k_);
        for(uint32_t share = 0; share < k_; share++) {
            preparedCommitments_[slot][share].reserve(numSlices);
            for(uint32_t slice = 0; slice < numSlices; slice++) {
                CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
                CryptoPP::ECPPoint commitment = curve.GetCurve().ScalarMultiply(G, r);
                preparedCommitments_[slot][share].push_back(std::pair(std::move(r), std::move(commitment)));
            }
        }
    }
}

std::vector<std::vector<std::vector<std::pair<CryptoPP::Integer, CryptoPP::ECPPoint>>>>& DCNetwork::preparedCommitments() {
    return preparedCommitments_;
}