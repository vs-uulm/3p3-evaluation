#include <cryptopp/oids.h>
#include "DCNetwork.h"
#include "../dc/Ready.h"
#include "../dc/Init.h"

#include <iostream>

DCNetwork::DCNetwork(uint32_t nodeID, size_t k, MessageQueue<ReceivedMessage>& inbox, MessageQueue<OutgoingMessage>& outbox)
: nodeID_(nodeID), k_(k), state_(std::make_unique<Init>()), inbox_(inbox), outbox_(outbox) {
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());
}

void DCNetwork::run() {
    for(;;) {
        state_ = state_->executeTask(*this);
    }
}

std::unordered_map<uint32_t, uint32_t>& DCNetwork::members() {
    return members_;
}

MessageQueue<ReceivedMessage>& DCNetwork::inbox() {
    return inbox_;
}
MessageQueue<OutgoingMessage>& DCNetwork::outbox() {
    return outbox_;
}

uint32_t DCNetwork::nodeID() {
    return nodeID_;
}

size_t DCNetwork::k() {
    return k_;
}

ECPPoint DCNetwork::commit(uint16_t r, uint32_t s) {
    ECPPoint first = ec_group.GetCurve().ScalarMultiply(G, r);
    ECPPoint second = ec_group.GetCurve().ScalarMultiply(H, s);
    ECPPoint C = ec_group.GetCurve().Add(first, second);
    return C;
}


/*
void phase_one(uint16_t msg_len) {
    // TODO member list has size of zero
    size_t k = memberList_.size();
    size_t slot_size = 4 + 32*k;
    uint8_t* msg1 = new uint8_t[2*k * slot_size]();

    if(msg_len > 0) {
        uint16_t p = PRNG.GenerateWord32(0, 2*k);
        uint16_t r = PRNG.GenerateWord32(0, USHRT_MAX);
        std::cout << "P: " << p << std::endl;
        std::cout << "R: " << r << std::endl;
        // TODO get random K values
        size_t slot_pos = p * slot_size;
    }

    delete msg1;
}
 */