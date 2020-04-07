#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include "Node.h"

Node::Node() {}

Node::Node(uint32_t nodeID, uint16_t port, const ip::address_v4& ip_address)
: nodeID_(nodeID), port_(port), ip_address_(ip_address) {}


Node::Node(uint32_t nodeID, const CryptoPP::ECPPoint& publicKey, uint16_t port, const ip::address_v4& ip_address)
: nodeID_(nodeID), port_(port), ip_address_(ip_address), publicKey_(publicKey) {}


uint32_t Node::nodeID() const {
    return nodeID_;
}

uint16_t Node::port() const {
    return port_;
}

const ip::address_v4& Node::ip_address() const {
    return ip_address_;
}

const CryptoPP::ECPPoint& Node::publicKey() const {
    return publicKey_;
}