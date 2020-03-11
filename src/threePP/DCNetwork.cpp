#include <cryptopp/oids.h>
#include "DCNetwork.h"
#include "../dc/ReadyState.h"
#include "../dc/InitState.h"

#include <iostream>

DCNetwork::DCNetwork(uint32_t nodeID, MessageQueue<ReceivedMessage>& inbox, MessageQueue<NetworkMessage>& outbox)
: state_(std::make_unique<InitState>()), inbox_(inbox), outbox_(outbox) {
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

}

void DCNetwork::add_member(uint32_t connectionID) {
    memberList_.push_back(connectionID);
}

void DCNetwork::remove_member(uint32_t connectionID) {
    memberList_.remove(connectionID);
}

ECPPoint DCNetwork::commit(uint16_t r, uint32_t s) {
    ECPPoint first = ec_group.GetCurve().ScalarMultiply(G, r);
    ECPPoint second = ec_group.GetCurve().ScalarMultiply(H, s);
    ECPPoint C = ec_group.GetCurve().Add(first, second);
    return C;
}

int send_msg(std::string& msg) {
    if(msg.length() > USHRT_MAX)
        return -1;
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