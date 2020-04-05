#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include "DCMember.h"

DCMember::DCMember(uint32_t nodeID, uint32_t connectionID)
: nodeID_(nodeID), connectionID_(connectionID ) {}

DCMember::DCMember(uint32_t nodeID, uint32_t connectionID, std::vector<uint8_t> encodedPK)
: nodeID_(nodeID), connectionID_(connectionID) {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());
    curve.GetCurve().DecodePoint(publicKey_, encodedPK.data(), curve.GetCurve().EncodedPointSize(true));
}

uint32_t DCMember::nodeID() {
    return nodeID_;
}

uint32_t DCMember::connectionID() {
    return connectionID_;
}

const CryptoPP::ECPPoint& DCMember::publicKey() {
    return publicKey_;
}