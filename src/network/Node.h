#ifndef THREEPP_NODE_H
#define THREEPP_NODE_H

#include <cstdint>
#include <boost/asio.hpp>
#include <cryptopp/ecpoint.h>

using namespace boost::asio;

class Node {
public:
    Node();

    Node(uint32_t nodeID, uint16_t port, const ip::address_v4& ip_address);

    Node(uint32_t nodeID, const CryptoPP::ECPPoint& PublicKey, uint16_t port, const ip::address_v4& ip_address);

    uint32_t nodeID() const;

    uint16_t port() const;

    const ip::address_v4& ip_address() const;

    const CryptoPP::ECPPoint& publicKey() const;
private:
    uint32_t nodeID_;

    uint16_t port_;

    ip::address_v4 ip_address_;

    CryptoPP::ECPPoint publicKey_;
};


#endif //THREEPP_NODE_H
