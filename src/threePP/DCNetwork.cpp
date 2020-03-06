#include <cryptopp/oids.h>
#include "DCNetwork.h"

#include <iostream>

DCNetwork::DCNetwork() : k(0) {

    ec_group.Initialize(CryptoPP::ASN1::secp256k1());
    bool G_test = ec_group.ValidateElement(3, G, nullptr);
    std::cout << "Success: " << G_test << std::endl;

    bool H_test = ec_group.ValidateElement(3, H, nullptr);
    std::cout << "Success: " << H_test << std::endl;
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

void DCNetwork::send_msg() {

}