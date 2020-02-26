#include "P2PConnection.h"

#include <iostream>

#include <boost/bind.hpp>

P2PConnection::P2PConnection(io_context& io_context_, ssl::context& ssl_context_,
        std::queue<std::shared_ptr<ReceivedMessage>>& msg_queue)
        : is_open_(false), ssl_socket_(io_context_, ssl_context_), msg_queue(msg_queue) {

}

P2PConnection::~P2PConnection() {
    disconnect();
}

int P2PConnection::connect(ip::address ip_address, uint16_t port) {
    try {
        ssl_socket_.lowest_layer().connect(tcp::endpoint(ip_address, port));
        ssl_socket_.handshake(ssl::stream_base::client);
    } catch (const boost::system::system_error& e) {
        std::cout << "Error" << std::endl;
        return -1;
    }
    is_open_ = true;
    async_read();
    return 0;
}

void P2PConnection::disconnect() {
    if (ssl_socket_.lowest_layer().is_open()) {
        try {
            ssl_socket_.shutdown();
            ssl_socket_.lowest_layer().shutdown(socket_base::shutdown_send);
            ssl_socket_.lowest_layer().close();
        } catch(std::exception& e) {
            std::cerr << "Could not properly shut down the connection" << std::endl;
        }
        is_open_ = false;
    }
}

void P2PConnection::async_handshake() {
    ssl_socket_.async_handshake(ssl::stream_base::server,
                                boost::bind(&P2PConnection::handshake_handler, this,
                                            placeholders::error));
}

void P2PConnection::handshake_handler(const boost::system::error_code& e) {
    if(e) {
        std::cerr << "Handshake Error:" << e.message() << std::endl;
    } else {
        async_read();
        is_open_ = true;
    }
}

void P2PConnection::async_read() {
    std::shared_ptr<ReceivedMessage> received_msg = std::make_shared<ReceivedMessage>(peerID);
    boost::asio::async_read(ssl_socket_,
                            boost::asio::buffer(received_msg->header()),
                            boost::bind(&P2PConnection::read_header,
                                    this,
                                    boost::asio::placeholders::error,
                                    received_msg));
}

void P2PConnection::read_header(const boost::system::error_code& e, std::shared_ptr<ReceivedMessage> received_msg) {
    if(e) {
        std::cerr << "Read Error: " << e.message() << std::endl;
    } else {
        received_msg->resize_body();
        boost::asio::async_read(ssl_socket_,
                                boost::asio::buffer(received_msg->body()),
                                boost::bind(&P2PConnection::read_body,
                                            this,
                                            boost::asio::placeholders::error,
                                            received_msg));
    }
}

void P2PConnection::read_body(const boost::system::error_code& e, std::shared_ptr<ReceivedMessage> received_msg) {
    if(e) {
        std::cerr << "Read Error: " << e.message() << std::endl;
    } else {
        msg_queue.push(received_msg);
        std::string msgString(received_msg->body().begin(), received_msg->body().end());
        std::cout << msgString << std::endl;
        async_read();
    }
}

void P2PConnection::send_msg(NetworkMessage& msg) {
    boost::system::error_code error;
    boost::asio::write(ssl_socket_, boost::asio::buffer(msg.header()), error);
    boost::asio::write(ssl_socket_, boost::asio::buffer(msg.body()), error);
}

ssl_socket& P2PConnection::socket() {
    return ssl_socket_;
}

bool P2PConnection::is_open() {
    return is_open_;
}
