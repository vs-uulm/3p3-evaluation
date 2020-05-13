#include <cryptopp/oids.h>
#include "DCNetwork.h"
#include "InitState.h"

DCNetwork::DCNetwork(DCMember self, size_t k, SecurityLevel securityLevel, CryptoPP::Integer privateKey, uint32_t numThreads,
        std::unordered_map<uint32_t, Node>& neigbors, MessageQueue<ReceivedMessage>& inboxDC,
        MessageQueue<OutgoingMessage>& outboxThreePP, MessageQueue<std::vector<uint8_t>>& outboxFinal)
: nodeID_(self.nodeID()), k_(k), securityLevel_(securityLevel), privateKey_(privateKey), numThreads_(numThreads), neighbors_(neigbors),
  inboxDC_(inboxDC), outboxThreePP_(outboxThreePP), outboxFinal_(outboxFinal), state_(std::make_unique<InitState>(*this)) {
    members_.insert(std::pair(nodeID_, self));
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

MessageQueue<std::vector<uint8_t>>& DCNetwork::outboxFinal() {
    return outboxFinal_;
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

CryptoPP::Integer & DCNetwork::privateKey() {
    return privateKey_;
}

SecurityLevel DCNetwork::securityLevel() {
    return securityLevel_;
}