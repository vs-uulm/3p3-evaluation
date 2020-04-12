#include <cryptopp/oids.h>
#include "DCNetwork.h"
#include "Ready.h"
#include "Init.h"

#include <iostream>

DCNetwork::DCNetwork(DCMember self, size_t k, std::unordered_map<uint32_t, Node>& neigbors, MessageQueue<ReceivedMessage>& inbox, MessageQueue<OutgoingMessage>& outbox)
: nodeID_(self.nodeID()), k_(k), neighbors_(neigbors), inbox_(inbox), outbox_(outbox), state_(std::make_unique<Init>(*this)) {
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
    return inbox_;
}
MessageQueue<OutgoingMessage>& DCNetwork::outbox() {
    return outbox_;
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
