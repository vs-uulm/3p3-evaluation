#include "p2p_connection.h"
#include <iostream>

#include <boost/bind.hpp>

p2p_connection::p2p_connection(io_context& io_context_, ssl::context& ssl_context_)
: ssl_socket_(io_context_, ssl_context_) {
}


p2p_connection::p2p_connection(io_context& io_context_, ssl::context& ssl_context_, uint16_t port, ip::address ip_address)
: ssl_socket_(io_context_, ssl_context_) {
    ssl_socket_.lowest_layer().connect(tcp::endpoint(ip_address, port));
}

p2p_connection::~p2p_connection() {
    if (ssl_socket_.lowest_layer().is_open()) {
        std::cout << "Shutting down connection" << std::endl;
        try {
            ssl_socket_.shutdown();
            ssl_socket_.lowest_layer().shutdown(socket_base::shutdown_send);
            ssl_socket_.lowest_layer().close();
        } catch(std::exception& e) {
            std::cout << "Connection could not be shut down properly" << std::endl;
            std::cout << "Reason: " << e.what() << std::endl;
        }
    }
}

void p2p_connection::open_connection() {
    ssl_socket_.async_handshake(ssl::stream_base::server,
                             boost::bind(&p2p_connection::handle_handshake, this,
                                         placeholders::error));
}

void p2p_connection::handle_handshake(const boost::system::error_code& error) {
    ssl_socket_.handshake(ssl::stream<tcp::socket>::client);
    ssl_socket_.async_read_some(boost::asio::buffer(data, 1024),
                                boost::bind(&p2p_connection::read_handler, this,
                                            placeholders::error,
                                            placeholders::bytes_transferred));
}

void p2p_connection::read_handler(const boost::system::error_code& error, size_t bytes_transferred) {
    if (!error) {
        ssl_socket_.async_read_some(buffer(data, 1024),
                boost::bind(&p2p_connection::read_handler, this,
                        placeholders::error,
                        placeholders::bytes_transferred));
        std::cout << data << std::endl;
    }
    else {
        delete this;
    }
}

void p2p_connection::send_data(std::string& data) {
    boost::system::error_code error;
    write(ssl_socket_, boost::asio::buffer(data.c_str(), data.length() + 1), error);
}

ssl_socket& p2p_connection::socket() {
    return ssl_socket_;
}
