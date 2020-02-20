#include "P2PConnection.h"
#include <iostream>

#include <boost/bind.hpp>

P2PConnection::P2PConnection(io_context& io_context_, ssl::context& ssl_context_, std::queue<std::string>& msg_queue)
: ssl_socket_(io_context_, ssl_context_), msg_queue(msg_queue) {
}


P2PConnection::P2PConnection(io_context& io_context_, ssl::context& ssl_context_, uint16_t port, ip::address ip_address, std::queue<std::string>& msg_queue)
: ssl_socket_(io_context_, ssl_context_), msg_queue(msg_queue) {
    ssl_socket_.lowest_layer().connect(tcp::endpoint(ip_address, port));
    ssl_socket_.handshake(ssl::stream_base::client);
}

P2PConnection::~P2PConnection() {
    if (ssl_socket_.lowest_layer().is_open()) {
        try {
            ssl_socket_.shutdown();
            ssl_socket_.lowest_layer().shutdown(socket_base::shutdown_send);
            ssl_socket_.lowest_layer().close();
        } catch(std::exception& e) {
            std::cout << "Could not properly shut down connection" << std::endl;
        }
    }
}

void P2PConnection::async_read() {

}

void P2PConnection::send_data(std::string& data) {
    boost::system::error_code error;
    boost::asio::write(ssl_socket_, boost::asio::buffer(data, data.length()), error);
}

void P2PConnection::read_data() {
    std::string content;
    content.resize(18);
    boost::system::error_code error;
    boost::asio::read(ssl_socket_, boost::asio::buffer(content), error);
    std::cout << content << std::endl;
}

ssl_socket& P2PConnection::socket() {
    return ssl_socket_;
}
