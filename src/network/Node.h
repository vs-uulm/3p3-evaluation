#ifndef THREEPP_NODE_H
#define THREEPP_NODE_H

#include <cstdint>
#include <boost/asio.hpp>

using namespace boost::asio;

class Node {
public:
    Node(uint32_t nodeID_, uint16_t port_, const std::string& ip_address_);

    Node(const Node& other);

    uint32_t nodeID();

    uint16_t port();

    ip::address ip_address();
private:
    uint32_t nodeID_;

    uint16_t port_;

    ip::address ip_address_;
};


#endif //THREEPP_NODE_H
