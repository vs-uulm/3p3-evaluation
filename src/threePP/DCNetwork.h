#ifndef THREEPP_DCNETWORK_H
#define THREEPP_DCNETWORK_H

#include <unordered_map>
#include <cstdlib>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include "../datastruct/MessageQueue.h"
#include "../datastruct/ReceivedMessage.h"
#include "../dc/DCNetworkState.h"

using namespace CryptoPP;

const ECPPoint G(CryptoPP::Integer("362dc3caf8a0e8afd06f454a6da0cdce6e539bc3f15e79a15af8aa842d7e3ec2h"),
                CryptoPP::Integer("b9f8addb295b0fd4d7c49a686eac7b34a9a11ed2d6d243ad065282dc13bce575h"));

const ECPPoint H(CryptoPP::Integer("a3cf0a4b6e1d9146c73e9a82e4bfdc37ee1587bc2bf3b0c19cb159ae362e38beh"),
                CryptoPP::Integer("db4369fabd3d770dd4c19d81ac69a1749963d69c687d7c4e12d186548b94cb2ah"));

class DCNetwork {
public:
    DCNetwork(uint32_t nodeID, MessageQueue<ReceivedMessage>& inbox, MessageQueue<NetworkMessage>& outbox);

    void add_member(uint32_t connectionID);

    void remove_member(uint32_t connectionID);
private:
    // The own nodeID
    uint32_t nodeID_;

    // list of nodes that participate in the DC-Network
    std::list<uint32_t> memberList_;


    MessageQueue<ReceivedMessage>& inbox_;
    MessageQueue<NetworkMessage>& outbox_;

    // current state of the DC network
    std::unique_ptr<DCNetworkState> state_;

    // reusable cryptoPP objects
    AutoSeededRandomPool PRNG;
    DL_GroupParameters_EC<ECP> ec_group;

    ECPPoint commit(uint16_t r, uint32_t s);
};


#endif //THREEPP_DCNETWORK_H
