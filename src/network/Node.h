#ifndef THREEPP_NODE_H
#define THREEPP_NODE_H

#include <cstdint>
#include <boost/asio.hpp>
#include <cryptopp/ecpoint.h>

using namespace boost::asio;

class Node {
public:
    Node(uint32_t nodeID, uint16_t port, const std::string& ip_address);

    Node(uint32_t nodeID, CryptoPP::Integer& privateKey, CryptoPP::ECPPoint& publicKey, uint16_t port, const std::string& ip_address);

    uint32_t nodeID() const;

    uint16_t port() const;

    const std::string& ip_address() const;

    const CryptoPP::Integer& privateKey() const;

    const CryptoPP::ECPPoint& publicKey() const;
private:
    uint32_t nodeID_;

    uint16_t port_;

    std::string ip_address_;

    CryptoPP::Integer privateKey_;

    CryptoPP::ECPPoint publicKey_;
};


#endif //THREEPP_NODE_H
