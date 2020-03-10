#include <cryptopp/oids.h>
#include "DCNetwork.h"
#include "../dc/ReadyState.h"

#include <iostream>

DCNetwork::DCNetwork() : state_(std::make_unique<ReadyState>()) {
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

    // TODO remove
    members.resize(8);
    /*
    bool G_test = ec_group.ValidateElement(3, G, nullptr);
    std::cout << "Success: " << G_test << std::endl;

    bool H_test = ec_group.ValidateElement(3, H, nullptr);
    std::cout << "Success: " << H_test << std::endl;
     */
}

void DCNetwork::add_member(uint32_t connectionID) {
    members.push_back(connectionID);
}

void DCNetwork::remove_member(uint32_t connectionID) {
    members.remove(connectionID);
}

EC_Point DCNetwork::commit(uint16_t r, uint32_t s) {
    EC_Point first = ec_group.GetCurve().ScalarMultiply(G, r);
    EC_Point second = ec_group.GetCurve().ScalarMultiply(H, s);
    EC_Point C = ec_group.GetCurve().Add(first, second);
    return C;
}

int send_msg(std::string& msg) {
    if(msg.length() > USHRT_MAX)
        return -1;
}

void phase_one(uint16_t msg_len) {
    size_t k = members.size();
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