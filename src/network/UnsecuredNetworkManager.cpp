#include "UnsecuredNetworkManager.h"
#include <boost/bind.hpp>
#include <iostream>

UnsecuredNetworkManager::UnsecuredNetworkManager(io_context& io_context, uint16_t port, MessageQueue<ReceivedMessage>& inbox)
        : io_context_(io_context), acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), maxConnectionID_(0), inbox_(inbox) {

    start_accept();
}

void UnsecuredNetworkManager::start_accept() {
    uint32_t connectionID = getConnectionID();

    auto new_connection = std::make_shared<UnsecuredP2PConnection>(connectionID, io_context_, inbox_);
    acceptor_.async_accept(new_connection->socket(),
                           boost::bind(&UnsecuredNetworkManager::accept_handler, this,
                                       placeholders::error, new_connection));
}

void UnsecuredNetworkManager::accept_handler(const boost::system::error_code& e, std::shared_ptr<UnsecuredP2PConnection> connection) {
    if(e) {
        std::cerr << "Accept Error:" << e.message() << std::endl;
    } else {
        connection->read();
        connections_.insert(std::pair(connection->connectionID(), connection));
        start_accept();
    }
}

int UnsecuredNetworkManager::addNeighbor(const Node &node) {
    uint32_t connectionID = getConnectionID();

    auto connection = std::make_shared<UnsecuredP2PConnection>(connectionID, io_context_, inbox_);

    for(int retryCount = 3; retryCount > 0; retryCount--) {
        if (connection->connect(node.ip_address(), node.port()) == 0) {

            connections_.insert(std::pair(connectionID, connection));
            return connectionID;
        }
        std::cout << "ConnectionID" << connectionID << std::endl;
        std::cout << "IP: " << node.ip_address().to_string() << " , Port: " << node.port() << std::endl;
        std::cout << "Connection refused: retrying after 500 milliseconds" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return -1;
}

int UnsecuredNetworkManager::connectToCA(const std::string& ip_address, uint16_t port) {
    uint32_t connectionID = getConnectionID();

    auto connection = std::make_shared<UnsecuredP2PConnection>(connectionID, io_context_, inbox_);
    for(int retryCount = 3; retryCount > 0; retryCount--) {
        if (connection->connect(ip::address_v4::from_string(ip_address), port) == 0) {
            connections_.insert(std::pair(connectionID, connection));
            return connectionID;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return -1;
}

int UnsecuredNetworkManager::sendMessage(OutgoingMessage msg) {

    if(msg.receiverID() == BROADCAST) {
        for (auto& connection : connections_) {
            if (connection.second->is_open()) {
                connection.second->send_msg(msg);
            }
        }
    } else {
        if (!connections_[msg.receiverID()]->is_open()) {
            std::cout << "Error" << std::endl;
            return -1;
        }
        connections_[msg.receiverID()]->send_msg(msg);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    return 0;
}

size_t UnsecuredNetworkManager::numConnections() {
    return connections_.size();
}

uint32_t UnsecuredNetworkManager::getConnectionID() {
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t connectionID = maxConnectionID_;
    maxConnectionID_++;
    return connectionID;
}
