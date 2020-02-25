#ifndef THREEPP_PEER_H
#define THREEPP_PEER_H

#include "P2PConnection.h"

#include <openssl/evp.h>

class Peer {
public:
    Peer(uint32_t nodeID, bool DC_member, std::vector<uint8_t>& raw_public_key);

    ~Peer();

    uint32_t nodeID();

    bool DC_member();

    EVP_PKEY* public_key();

private:
    uint32_t nodeID_;

    bool DC_member_;

    EVP_PKEY* public_key_;
};


#endif //THREEPP_PEER_H
