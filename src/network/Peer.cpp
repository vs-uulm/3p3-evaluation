#include "Peer.h"

#include "../crypto/Utils.h"

Peer::Peer(uint32_t nodeID, bool DC_member, std::vector<uint8_t>& raw_public_key)
: nodeID_(nodeID), DC_member_(DC_member), public_key_(utils::process_raw_public_key(raw_public_key)) {}

Peer::~Peer() {
    EVP_PKEY_free(public_key_);
}

uint32_t Peer::nodeID() {
    return nodeID_;
}

bool Peer::DC_member() {
    return DC_member_;
}

EVP_PKEY* Peer::public_key() {
    return public_key_;
}


