#include "NetworkManager.h"

#include <boost/bind.hpp>
#include <iostream>

NetworkManager::NetworkManager(io_context& io_context_, uint16_t port)
: io_context_(io_context_), ssl_context_(ssl::context::sslv23),
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
        std::cout << "Accept Error:" << e.message() << std::endl;
    } else {
        connections.push_back(connection);
        connection->async_handshake();
        start_accept();
    }

}

void NetworkManager::broadcast(const std::string &msg) {
    for(auto connection : connections) {
        connection->send_data(msg);
    }
}
