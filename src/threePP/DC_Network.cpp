#include <cryptopp/oids.h>
#include "DC_Network.h"

#include <iostream>

DC_Network::DC_Network(size_t seed_len) : seed_len_(seed_len), state(READY) {
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

void DC_Network::add_member(uint32_t connectionID) {
    members.push_back(connectionID);
}

void DC_Network::remove_member(uint32_t connectionID) {
    members.remove(connectionID);
}

EC_Point DC_Network::commit(uint16_t r, uint32_t s) {
    EC_Point first = ec_group.GetCurve().ScalarMultiply(G, r);
    EC_Point second = ec_group.GetCurve().ScalarMultiply(H, s);
    EC_Point C = ec_group.GetCurve().Add(first, second);
    return C;
}

int DC_Network::send_msg(std::string& msg) {
    if(msg.length() > USHRT_MAX)
        return -1;

    phase_one(msg.length());
}

void DC_Network::phase_one(uint16_t msg_len) {
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