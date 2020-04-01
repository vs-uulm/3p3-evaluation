#include "NetworkManager.h"

#include <boost/bind.hpp>
#include <iostream>

NetworkManager::NetworkManager(io_context& io_context, uint16_t port, MessageQueue<ReceivedMessage>& inbox)
: io_context_(io_context), ssl_context_(ssl::context::sslv23),
  acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), maxConnectionID_(0), inbox_(inbox) {

    ssl_context_.set_options(ssl::context::default_workarounds |
                             ssl::context::no_sslv2 |
                             ssl::context::no_sslv3);
    ssl_context_.use_private_key_file("../cert/private.pem", ssl::context::pem);
    ssl_context_.use_certificate_chain_file("../cert/server_cert.pem");

    start_accept();
}

void NetworkManager::start_accept() {
    uint32_t connectionID;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        connectionID = maxConnectionID_;
        maxConnectionID_++;
    }
    auto new_connection = std::make_shared<P2PConnection>(connectionID, io_context_, ssl_context_, inbox_);
    acceptor_.async_accept(new_connection->socket().lowest_layer(),
                           boost::bind(&NetworkManager::accept_handler, this,
                                       placeholders::error, new_connection));
}

void NetworkManager::accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection) {
    if(e) {
        std::cerr << "Accept Error:" << e.message() << std::endl;
    } else {
        connection->async_handshake();
        connections_.insert(std::pair(connection->connectionID(), connection));
        start_accept();
    }
}

uint32_t NetworkManager::addNeighbor(uint32_t nodeID, const Node &node) {
    uint32_t connectionID;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        connectionID = maxConnectionID_;
        maxConnectionID_++;
    }
    auto connection = std::make_shared<P2PConnection>(connectionID, io_context_, ssl_context_, inbox_);
    int retry_count = 3;

    while(retry_count-- > 0) {
        if(connection->connect(node.ip_address(), node.port()) == 0)
            break;
        std::cout << "Connection refused: retrying after 500 milliseconds" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    NetworkMessage helloMessage(0, nodeID);

    connection->send_msg(helloMessage);
    connections_.insert(std::pair(connection->connectionID(), connection));

    return connectionID;
}

int NetworkManager::sendMessage(OutgoingMessage& msg) {
    if(msg.receiverID() == BROADCAST) {
        for (auto& connection : connections_) {
            if (connection.second->is_open()) {
                connection.second->send_msg(msg);
            }
        }
    } else {
        if (!connections_[msg.receiverID()]->is_open())
            return -1;
        connections_[msg.receiverID()]->send_msg(msg);
    }
    return 0;
}
