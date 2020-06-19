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
        storeConnection(connection);
        storeNeighbor(connection->connectionID());
        start_accept();
    }
}

int UnsecuredNetworkManager::addNeighbor(const Node &node) {
    uint32_t connectionID = getConnectionID();

    auto connection = std::make_shared<UnsecuredP2PConnection>(connectionID, io_context_, inbox_);

    for(int retryCount = 3; retryCount > 0; retryCount--) {
        if (connection->connect(node.ip_address(), node.port()) == 0) {

            storeConnection(connection);
            storeNeighbor(connectionID);
            return connectionID;
        }
        std::cout << "ConnectionID" << connectionID << std::endl;
        std::cout << "IP: " << node.ip_address().to_string() << " , Port: " << node.port() << std::endl;
        std::cout << "Connection refused: retrying after 500 milliseconds" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return -1;
}

void UnsecuredNetworkManager::connectToCA(const std::string& ip_address, uint16_t port) {
    centralInstance_ = std::make_shared<UnsecuredP2PConnection>(CENTRAL, io_context_, inbox_);
    while(centralInstance_->connect(ip::address_v4::from_string(ip_address), port) != 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

int UnsecuredNetworkManager::sendMessage(OutgoingMessage msg) {
    if(msg.receiverID() == BROADCAST) {
        for (auto& connection : connections_) {
            if (connection.second->is_open()) {
                connection.second->send(std::move(msg));
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
            return -1;
        }
        if (!connections_[msg.receiverID()]->is_open())
            return -1;
        connections_[msg.receiverID()]->send(std::move(msg));
    }
    return 0;
}

uint32_t UnsecuredNetworkManager::getConnectionID() {
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t connectionID = maxConnectionID_;
    maxConnectionID_++;
    return connectionID;
}

std::vector<uint32_t>& UnsecuredNetworkManager::neighbors() {
    return neighbors_;
}

void UnsecuredNetworkManager::storeNeighbor(uint32_t connectionID) {
    std::lock_guard<std::mutex> lock(mutex_);
    neighbors_.push_back(connectionID);
}

void UnsecuredNetworkManager::storeConnection(std::shared_ptr<UnsecuredP2PConnection> connection) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_.insert(std::pair(connection->connectionID(), connection));
}

void UnsecuredNetworkManager::terminate() {
    for(auto& connection : connections_)
        connection.second->disconnect();
    centralInstance_->disconnect();
}
