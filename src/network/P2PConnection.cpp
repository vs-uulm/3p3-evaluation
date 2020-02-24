#include "P2PConnection.h"
#include "NetworkMessage.h"
#include <iostream>

#include <boost/bind.hpp>

P2PConnection::P2PConnection(io_context& io_context_, ssl::context& ssl_context_,
        std::queue<std::shared_ptr<NetworkMessage>>& msg_queue)
        : ssl_socket_(io_context_, ssl_context_), msg_queue(msg_queue) {

}


P2PConnection::P2PConnection(io_context& io_context_, ssl::context& ssl_context_, uint16_t port,
        ip::address ip_address, std::queue<std::shared_ptr<NetworkMessage>>& msg_queue)
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

void P2PConnection::async_handshake() {
    ssl_socket_.async_handshake(ssl::stream_base::server,
                                boost::bind(&P2PConnection::handshake_handler, this,
                                            placeholders::error));
}

void P2PConnection::handshake_handler(const boost::system::error_code& e) {
    if(e) {
        std::cout << "Handshake Error:" << e.message() << std::endl;
    } else {
        async_read();
    }
}

void P2PConnection::async_read() {
    std::shared_ptr<NetworkMessage> msg = std::make_shared<NetworkMessage>();
    boost::asio::async_read(ssl_socket_,
                            boost::asio::buffer((uint8_t*) msg->header(),4),
                            boost::bind(&P2PConnection::read_header,
                                    this,
                                    boost::asio::placeholders::error,
                                    msg));
}

void P2PConnection::read_header(const boost::system::error_code& e, std::shared_ptr<NetworkMessage> msg) {
    if(e) {
        std::cout << "Read Error: " << e.message() << std::endl;
    } else {
        msg_queue.push(msg);
        async_read();
    }
}

void P2PConnection::read_body(const boost::system::error_code& e, std::shared_ptr<NetworkMessage> msg) {
    if(e) {
        std::cout << "Read Error: " << e.message() << std::endl;
    } else {
        msg_queue.push(msg);
        async_read();
    }
}

void P2PConnection::send_data(std::shared_ptr<NetworkMessage>& message) {
    boost::system::error_code error;
    boost::asio::write(ssl_socket_, boost::asio::buffer(message->header(), 4), error);
    boost::asio::write(ssl_socket_, boost::asio::buffer(message->body(), message->body_len()), error);
}

ssl_socket& P2PConnection::socket() {
    return ssl_socket_;
}
