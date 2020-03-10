#include "NetworkManager.h"

#include <boost/bind.hpp>
#include <iostream>

NetworkManager::NetworkManager(io_context& io_context, uint16_t port, MessageQueue<ReceivedMessage>& inbox)
: io_context_(io_context), ssl_context_(ssl::context::sslv23), inbox_(inbox),
  maxConnectionID(0), acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {

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
        connectionID = maxConnectionID;
        maxConnectionID++;
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
        connections_.push_back(connection);
        start_accept();
    }
}

uint32_t NetworkManager::addNeighbor(uint32_t nodeID, const Node &node) {
    uint32_t connectionID;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        connectionID = maxConnectionID;
        maxConnectionID++;
    }
    auto new_connection = std::make_shared<P2PConnection>(connectionID, io_context_, ssl_context_, inbox_);
    int retry_count = 3;

    while(retry_count-- > 0) {
        if(new_connection->connect(node.ip_address(), node.port()) == 0)
            break;
        std::cout << "Connection refused: retrying after 500 milliseconds" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // a hello message is sent to introduce the node to the new neighbor
    std::vector<uint8_t> nodeIDVector(reinterpret_cast<uint8_t*>(&nodeID),
            reinterpret_cast<uint8_t*>(&nodeID) + sizeof(uint32_t));
    NetworkMessage helloMessage(0, nodeIDVector);

    new_connection->send_msg(helloMessage);
    connections_.push_back(new_connection);

    // TODO return connectionID
    return connectionID;
}

void NetworkManager::floodAndPrune(NetworkMessage& msg) {
    for(auto connection : connections_) {
        if(connection->is_open()) {
            connection->send_msg(msg);
        }
    }
}
