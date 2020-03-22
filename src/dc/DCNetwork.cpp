#include <cryptopp/oids.h>
#include "DCNetwork.h"
#include "Ready.h"
#include "Init.h"

#include <iostream>

DCNetwork::DCNetwork(uint32_t nodeID, size_t k, MessageQueue<ReceivedMessage>& inbox, MessageQueue<OutgoingMessage>& outbox)
: nodeID_(nodeID), k_(k), inbox_(inbox), outbox_(outbox), state_(std::make_unique<Init>(*this)) {
    members_.insert(std::pair(nodeID, SELF));
}

void DCNetwork::run() {
    for(int i = 0; i < 3; i++) {
        state_ = state_->executeTask();
    }
}

std::map<uint32_t, uint32_t>& DCNetwork::members() {
    return members_;
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
