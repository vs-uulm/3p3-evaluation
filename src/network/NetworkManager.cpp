#include "NetworkManager.h"
#include "../datastruct/MessageType.h"
#include <boost/bind.hpp>
#include <iostream>

NetworkManager::NetworkManager(io_context& io_context, uint16_t port, MessageQueue<ReceivedMessage>& inbox)
        : io_context_(io_context), acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), maxConnectionID_(0), inbox_(inbox) {

    start_accept();
}

void NetworkManager::start_accept() {
    uint32_t connectionID = getConnectionID();

    auto new_connection = std::make_shared<UnsecuredP2PConnection>(connectionID, io_context_, inbox_);
    acceptor_.async_accept(new_connection->socket(),
                           boost::bind(&NetworkManager::accept_handler, this,
                                       placeholders::error, new_connection));
}

void NetworkManager::accept_handler(const boost::system::error_code& e, std::shared_ptr<UnsecuredP2PConnection> connection) {
    if(e) {
        std::cerr << "Accept Error:" << e.message() << std::endl;
    } else {
        connection->read();
        storeConnection(connection);
        storeNeighbor(connection->connectionID());
        start_accept();
    }
}

int NetworkManager::addNeighbor(const Node &node) {
    uint32_t connectionID = getConnectionID();

    auto connection = std::make_shared<UnsecuredP2PConnection>(connectionID, io_context_, inbox_);

    for(int retryCount = 20; retryCount > 0; retryCount--) {
        if (connection->connect(node.ip_address(), node.port()) == 0) {
            storeConnection(connection);
            storeNeighbor(connectionID);
            return connectionID;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return -1;
}

void NetworkManager::connectToCA(const std::string& ip_address, uint16_t port) {
    centralInstance_ = std::make_shared<UnsecuredP2PConnection>(CENTRAL, io_context_, inbox_);
    while(centralInstance_->connect(ip::address_v4::from_string(ip_address), port) != 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

int NetworkManager::sendMessage(OutgoingMessage msg) {
    std::lock_guard<std::mutex> lock(connectionMutex_);
    if(msg.receiverID() == BROADCAST) {
        for (auto& connection : connections_) {
            if (connection.second->is_open()) {
                connection.second->send(msg);
            }
        }
    } else if(msg.receiverID() == SELF) {
        ReceivedMessage receivedMessage(SELF, msg.header()[0], SELF, msg.body());
        inbox_.push(std::move(receivedMessage));
    } else if(msg.receiverID() == CENTRAL) {
        if (!centralInstance_->is_open())
            return -1;
        centralInstance_->send(std::move(msg));
    } else {
        if(connections_.count(msg.receiverID()) < 1) {
            std::cerr << "Connection " << msg.receiverID() << " not available" << std::endl;
            return -1;
        }
        if (!connections_[msg.receiverID()]->is_open()) {
            return -1;
        }
        connections_[msg.receiverID()]->send(std::move(msg));
    }
    return 0;
}

uint32_t NetworkManager::getConnectionID() {
    std::lock_guard<std::mutex> lock(connectionMutex_);
    uint32_t connectionID = maxConnectionID_;
    maxConnectionID_++;
    return connectionID;
}

std::vector<uint32_t> NetworkManager::neighbors() {
    std::lock_guard<std::mutex> lock(neighborMutex_);
    std::vector<uint32_t> neighborsCopy(neighbors_);
    return neighborsCopy;
}

void NetworkManager::storeNeighbor(uint32_t connectionID) {
    std::lock_guard<std::mutex> lock(connectionMutex_);
    neighbors_.push_back(connectionID);
}

void NetworkManager::storeConnection(std::shared_ptr<UnsecuredP2PConnection> connection) {
    std::lock_guard<std::mutex> lock(connectionMutex_);
    if(connections_.count(connection->connectionID()) > 0) {
        std::cerr << "Error Neighbour already inserted" << std::endl;
        exit(1);
    }
    connections_.insert(std::pair(connection->connectionID(), connection));
}

void NetworkManager::terminate() {
    for(auto& connection : connections_)
        connection.second->disconnect();
    if(centralInstance_)
        centralInstance_->disconnect();
}
