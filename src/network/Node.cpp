#include "Node.h"

Node::Node(uint32_t nodeID_, uint16_t port_, const std::string& ip_address_)
: nodeID(nodeID_), port(port_), ip_address(ip::address::from_string(ip_address_)){}


Node::Node(const Node& other)
: nodeID(other.nodeID), port(other.port), ip_address(other.ip_address) {}