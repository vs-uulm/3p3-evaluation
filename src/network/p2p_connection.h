#ifndef THREEPP_P2P_CONNECTION_H
#define THREEPP_P2P_CONNECTION_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using namespace boost::asio;
using ip::tcp;

typedef ssl::stream<tcp::socket> ssl_socket;

class p2p_connection {
public:
    p2p_connection(io_context& io_context_, ssl::context& ssl_context_);

    p2p_connection(io_context& io_context_, ssl::context& ssl_context_, uint16_t port, ip::address ip_address);

    ~p2p_connection();

    void open_connection();

    // TODD read node ID
    void handle_handshake(const boost::system::error_code& error);

    void read_handler(const boost::system::error_code& error,
                      size_t bytes_transferred);

    ssl_socket& socket();

    void send_data(std::string& data);

private:
    char data[1024];
    ssl_socket ssl_socket_;
};



#endif //THREEPP_P2P_CONNECTION_H
