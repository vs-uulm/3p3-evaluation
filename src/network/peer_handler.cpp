#include "peer_handler.h"
#include "p2p_connection.h"
#include <boost/bind.hpp>
#include <iostream>

peer_handler::peer_handler(io_context& io_context_, uint16_t listener_port)
: io_context_(io_context_), ssl_context_(ssl::context::sslv23),
  acceptor_(io_context_, tcp::endpoint(tcp::v4(), listener_port)) {

    ssl_context_.set_options(ssl::context::default_workarounds |
                            ssl::context::no_sslv2 |
                            ssl::context::no_sslv3);
    ssl_context_.use_private_key_file("../cert/private.pem", ssl::context::pem);
    ssl_context_.use_certificate_chain_file("../cert/server_cert.pem");

    accept();
}

void peer_handler::accept() {
    p2p_connection* new_connection = new p2p_connection(io_context_, ssl_context_);

    acceptor_.async_accept(new_connection->socket().lowest_layer(),
                           boost::bind(&peer_handler::accept_handler, this, new_connection,
                                       placeholders::error));
}

void peer_handler::accept_handler(p2p_connection* new_connection, const boost::system::error_code &ec) {
    if(!ec) {
        std::cout << "Accepted!" << std::endl;
        new_connection->open_connection();
    } else {
        std::cout << "Error: " << ec.message() << std::endl;
    }
    accept();
}