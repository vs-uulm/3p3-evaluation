#include "P2PConnection.h"

#include <iostream>

#include <boost/bind.hpp>
#include <iomanip>

P2PConnection::P2PConnection(uint32_t connectionID, io_context& io_context_, ssl::context& ssl_context_, MessageQueue<ReceivedMessage>& inbox)
: is_open_(false), connectionID_(connectionID), ssl_socket_(io_context_, ssl_context_), inbox_(inbox) {}

P2PConnection::~P2PConnection() {
    disconnect();
}

int P2PConnection::connect(ip::address_v4 ip_address, uint16_t port) {
    try {
        ssl_socket_.lowest_layer().connect(tcp::endpoint(ip_address, port));
        ssl_socket_.handshake(ssl::stream_base::client);
    } catch (const boost::system::system_error& e) {
        std::cout << "Error: could not open connection" << std::endl;
        return -1;
    }
    is_open_ = true;
    read();
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
        read();
        is_open_ = true;
    }
}

void P2PConnection::read() {
    auto received_msg = std::make_shared<ReceivedMessage>(connectionID_);
    boost::asio::async_read(ssl_socket_,
                            boost::asio::buffer(received_msg->header()),
                            boost::bind(&P2PConnection::read_header,
                                    this,
                                    boost::asio::placeholders::error,
                                    received_msg));
}

void P2PConnection::read_header(const boost::system::error_code& e, std::shared_ptr<ReceivedMessage> received_msg) {
    if(e) {
        std::cerr << "Could not read the message header from connection: " << connectionID_ << std::endl;
    } else {
        received_msg->resizeBody();
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
        std::cerr << "Could not read the message body from connection: " << connectionID_ << std::endl;
        for (uint8_t c : received_msg->header())
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int) c << " ";
        std::cerr << std::endl;
    }
    inbox_.push(std::move(*received_msg));
    read();

}

void P2PConnection::send_msg(NetworkMessage msg) {
    std::vector<boost::asio::const_buffer> combined;
    combined.push_back(boost::asio::buffer(msg.header()));
    combined.push_back(boost::asio::buffer(msg.body()));

    boost::system::error_code error;
    boost::asio::write(ssl_socket_, combined, error);
    if(error)
        std::cerr << "Error: could not send message" << std::endl;
}

bool P2PConnection::is_open() {
    return is_open_;
}

ssl_socket& P2PConnection::socket() {
    return ssl_socket_;
}

uint32_t P2PConnection::connectionID() {
    return connectionID_;
}
