#ifndef THREEPP_DCNETWORK_H
#define THREEPP_DCNETWORK_H

#include <unordered_map>
#include <cstdlib>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include "../datastruct/MessageQueue.h"
#include "../datastruct/ReceivedMessage.h"
#include "../dc/DCState.h"
#include "../datastruct/OutgoingMessage.h"

using namespace CryptoPP;

const ECPPoint G(CryptoPP::Integer("362dc3caf8a0e8afd06f454a6da0cdce6e539bc3f15e79a15af8aa842d7e3ec2h"),
                CryptoPP::Integer("b9f8addb295b0fd4d7c49a686eac7b34a9a11ed2d6d243ad065282dc13bce575h"));

const ECPPoint H(CryptoPP::Integer("a3cf0a4b6e1d9146c73e9a82e4bfdc37ee1587bc2bf3b0c19cb159ae362e38beh"),
                CryptoPP::Integer("db4369fabd3d770dd4c19d81ac69a1749963d69c687d7c4e12d186548b94cb2ah"));


class DCNetwork {
public:
    DCNetwork(uint32_t nodeID, size_t k, MessageQueue<ReceivedMessage>& inbox, MessageQueue<OutgoingMessage>& outbox);

    std::unordered_map<uint32_t, uint32_t>& members();

    MessageQueue<ReceivedMessage>& inbox();

    MessageQueue<OutgoingMessage>& outbox();

    uint32_t nodeID();

    size_t k();

    void run();

private:
    uint32_t nodeID_;

    size_t k_;

    // mapping the nodeIDs to the connectionIDs
    std::unordered_map<uint32_t, uint32_t> members_;

    MessageQueue<ReceivedMessage>& inbox_;
    MessageQueue<OutgoingMessage>& outbox_;

    // current state of the DC network
    std::unique_ptr<DCState> state_;

    // reusable cryptoPP objects
    AutoSeededRandomPool PRNG;
    DL_GroupParameters_EC<ECP> ec_group;

    ECPPoint commit(uint16_t r, uint32_t s);
};


#endif //THREEPP_DCNETWORK_H
