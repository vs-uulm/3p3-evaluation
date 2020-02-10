#ifndef THREEPP_PEER_HANDLER_H
#define THREEPP_PEER_HANDLER_H

#include <cstdint>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "p2p_connection.h"

using namespace boost::asio;
using ip::tcp;

class peer_handler {
public:
    peer_handler(io_context& io_context_, uint16_t listener_port);
    void accept();
    void accept_handler(p2p_connection* new_connection, const boost::system::error_code &ec);
private:
    io_context& io_context_;
    ssl::context ssl_context_;
    tcp::acceptor acceptor_;
};


#endif //THREEPP_PEER_HANDLER_H
