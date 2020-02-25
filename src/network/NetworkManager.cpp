#include "NetworkManager.h"

#include <boost/bind.hpp>
#include <iostream>

NetworkManager::NetworkManager(io_context& io_context_, uint16_t port)
: con_ctr(0), io_context_(io_context_), ssl_context_(ssl::context::sslv23),
  acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)) {

    ssl_context_.set_options(ssl::context::default_workarounds |
                             ssl::context::no_sslv2 |
                             ssl::context::no_sslv3);
    ssl_context_.use_private_key_file("../cert/private.pem", ssl::context::pem);
    ssl_context_.use_certificate_chain_file("../cert/server_cert.pem");
    start_accept();
}

void NetworkManager::start_accept() {
    std::shared_ptr<P2PConnection> new_connection = std::make_shared<P2PConnection>(io_context_, ssl_context_, msg_queue);
    acceptor_.async_accept(new_connection->socket().lowest_layer(),
                           boost::bind(&NetworkManager::accept_handler, this,
                                       placeholders::error, new_connection));
}

void NetworkManager::accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection) {
    if(e) {
        std::cerr << "Accept Error:" << e.message() << std::endl;
    } else {
        connection->async_handshake();
        connections.push_back(connection);
        start_accept();
    }
}

int NetworkManager::add_neighbor(const Node &node) {
    std::shared_ptr<P2PConnection> new_connection = std::make_shared<P2PConnection>(io_context_, ssl_context_, msg_queue);
    int retry_count = 3;
    while(retry_count-- > 0) {
        if(new_connection->connect(node.ip_address(), node.port()) == 0)
            break;
        std::cout << "Connection refused: retry in 500 milliseconds" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return retry_count;
}

void NetworkManager::broadcast(NetworkMessage& message) {
    for(auto connection : connections) {
        if(connection->is_open()) {
            connection->send_msg(message);
        }
    }
}
