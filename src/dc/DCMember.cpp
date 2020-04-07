#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include "DCMember.h"

DCMember::DCMember(uint32_t nodeID, uint32_t connectionID)
: nodeID_(nodeID), connectionID_(connectionID ) {}

DCMember::DCMember(uint32_t nodeID, uint32_t connectionID, CryptoPP::ECPPoint publicKey)
: nodeID_(nodeID), connectionID_(connectionID), publicKey_(publicKey) {}

uint32_t DCMember::nodeID() {
    return nodeID_;
}

uint32_t DCMember::connectionID() {
    return connectionID_;
}

const CryptoPP::ECPPoint& DCMember::publicKey() {
    return publicKey_;
}