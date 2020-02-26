#include "Node.h"

Node::Node(uint32_t nodeID, uint16_t port, const std::string& ip_address)
: nodeID_(nodeID), port_(port), ip_address_(ip::address::from_string(ip_address)){}


Node::Node(const Node& other)
: nodeID_(other.nodeID_), port_(other.port_), ip_address_(other.ip_address_) {}


uint32_t Node::nodeID() const {
    return nodeID_;
}

uint16_t Node::port() const {
    return port_;
}

ip::address Node::ip_address() const {
    return ip_address_;
}