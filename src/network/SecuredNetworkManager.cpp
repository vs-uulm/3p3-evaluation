#include "SecuredNetworkManager.h"
#include <boost/bind.hpp>
#include <iostream>

SecuredNetworkManager::SecuredNetworkManager(io_context& io_context, uint16_t port, MessageQueue<ReceivedMessage>& inbox)
: io_context_(io_context), ssl_context_(ssl::context::sslv23),
  acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), maxConnectionID_(0), inbox_(inbox) {

    ssl_context_.set_options(ssl::context::default_workarounds |
                             ssl::context::no_sslv2 |
                             ssl::context::no_sslv3);
    ssl_context_.use_private_key_file("../cert/private.pem", ssl::context::pem);
    ssl_context_.use_certificate_chain_file("../cert/server_cert.pem");

    start_accept();
}

void SecuredNetworkManager::start_accept() {
    uint32_t connectionID = getConnectionID();
    auto new_connection = std::make_shared<P2PConnection>(connectionID, io_context_, ssl_context_, inbox_);
    acceptor_.async_accept(new_connection->socket().lowest_layer(),
                           boost::bind(&SecuredNetworkManager::accept_handler, this,
                                       placeholders::error, new_connection));
}

void SecuredNetworkManager::accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection) {
    if(e) {
        std::cerr << "Accept Error:" << e.message() << std::endl;
    } else {
        connection->async_handshake();
        storeConnection(connection);
        storeNeighbor(connection->connectionID());
        start_accept();
    }
}

int SecuredNetworkManager::addNeighbor(const Node &node) {
    uint32_t connectionID = getConnectionID();
    auto connection = std::make_shared<P2PConnection>(connectionID, io_context_, ssl_context_, inbox_);

    for(int retryCount = 5; retryCount > 0; retryCount--) {
        if (connection->connect(node.ip_address(), node.port()) == 0) {
            storeConnection(connection);
            storeNeighbor(connectionID);
            return connectionID;
        }
        std::cout << "ConnectionID" << connectionID << std::endl;
        std::cout << "IP: " << node.ip_address().to_string() << " , Port: " << node.port() << std::endl;
        std::cout << "Connection refused: retrying after 200 milliseconds" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    return -1;
}

void SecuredNetworkManager::connectToCA(const std::string& ip_address, uint16_t port) {
    centralInstance_ = std::make_shared<P2PConnection>(CENTRAL, io_context_, ssl_context_, inbox_);
    while(centralInstance_->connect(ip::address_v4::from_string(ip_address), port) != 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

uint32_t SecuredNetworkManager::getConnectionID() {
    std::lock_guard<std::mutex> lock(connectionMutex_);
    uint32_t connectionID = maxConnectionID_;
    maxConnectionID_++;
    return connectionID;
}

int SecuredNetworkManager::sendMessage(OutgoingMessage msg) {
    std::lock_guard<std::mutex> lock(connectionMutex_);
    if(msg.receiverID() == BROADCAST) {
        for(auto& connection : connections_)
            if(connection.second->is_open())
                connection.second->send(msg);
    } else if(msg.receiverID() == SELF) {
        ReceivedMessage receivedMessage(SELF, msg.header()[0], SELF, msg.body());
        inbox_.push(std::move(receivedMessage));
    } else if(msg.receiverID() == CENTRAL) {
        if (!centralInstance_->is_open())
            return -1;
        centralInstance_->send(msg);
    } else {
        if(connections_.count(msg.receiverID()) < 1) {
            std::cout << msg.receiverID() << std::endl;
            return -1;
        }
        if(!connections_[msg.receiverID()]->is_open())
            return -1;
        connections_[msg.receiverID()]->send(msg);
    }
    return 0;
}

std::vector<uint32_t> SecuredNetworkManager::neighbors() {
    return neighbors_;
}

void SecuredNetworkManager::storeNeighbor(uint32_t connectionID) {
    std::lock_guard<std::mutex> lock(neighborMutex_);
    neighbors_.push_back(connectionID);
}

void SecuredNetworkManager::storeConnection(std::shared_ptr<P2PConnection> connection) {
    std::lock_guard<std::mutex> lock(connectionMutex_);
    connections_.insert(std::pair(connection->connectionID(), connection));
}

void SecuredNetworkManager::terminate() {
    for(auto& connection : connections_)
        connection.second->disconnect();
    centralInstance_->disconnect();
}
