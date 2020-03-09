#ifndef THREEPP_DC_NETWORK_H
#define THREEPP_DC_NETWORK_H

#include <unordered_map>
#include <cstdlib>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include "../datastruct/MessageQueue.h"
#include "../datastruct/ReceivedMessage.h"

typedef CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element EC_Point;

const EC_Point G(CryptoPP::Integer("362dc3caf8a0e8afd06f454a6da0cdce6e539bc3f15e79a15af8aa842d7e3ec2h"),
                CryptoPP::Integer("b9f8addb295b0fd4d7c49a686eac7b34a9a11ed2d6d243ad065282dc13bce575h"));

const EC_Point H(CryptoPP::Integer("a3cf0a4b6e1d9146c73e9a82e4bfdc37ee1587bc2bf3b0c19cb159ae362e38beh"),
                CryptoPP::Integer("db4369fabd3d770dd4c19d81ac69a1749963d69c687d7c4e12d186548b94cb2ah"));

enum DC_State {
    READY,
    ROUND1_PHASE1,
    ROUND1_PHASE2,
    ROUND1_PHASE3,
    ROUND1_PHASE4
};

// A simple class to represent one slot in the first message of the first round
template<size_t N>
class Slot {
public:
Slot() : r(0), l(0), K{0} {};
    uint16_t r;
    uint16_t l;
    std::array<std::array<uint8_t, 32>, N> K;
};



class DC_Network {
public:
    DC_Network(size_t seed_len);

    void add_member(uint32_t connectionID);

    void remove_member(uint32_t connectionID);

    int send_msg(std::string& msg);

private:
    // Length of the seeds K for round two
    size_t seed_len_;

    // Neighbour nodes that participate in the DC-Network
    std::list<uint32_t> members;

    // current state of the DC network
    DC_State state;

    // reusable cryptoPP objects
    CryptoPP::AutoSeededRandomPool PRNG;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;

    void phase_one(uint16_t msg_len);

    EC_Point commit(uint16_t r, uint32_t s);
};


#endif //THREEPP_DC_NETWORK_H
