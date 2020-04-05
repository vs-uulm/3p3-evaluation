#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include "Node.h"


Node::Node(uint32_t nodeID, uint16_t port, const std::string& ip_address)
: nodeID_(nodeID), port_(port), ip_address_(ip_address) {}


Node::Node(uint32_t nodeID, CryptoPP::Integer& privateKey, CryptoPP::ECPPoint& publicKey, uint16_t port, const std::string& ip_address)
: nodeID_(nodeID), port_(port), ip_address_(ip_address), privateKey_(privateKey), publicKey_(publicKey) {}


uint32_t Node::nodeID() const {
    return nodeID_;
}

uint16_t Node::port() const {
    return port_;
}

const std::string& Node::ip_address() const {
    return ip_address_;
}

const CryptoPP::Integer & Node::privateKey() const {
    return privateKey_;
}

const CryptoPP::ECPPoint & Node::publicKey() const {
    return publicKey_;
}