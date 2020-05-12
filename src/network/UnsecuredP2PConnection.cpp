#include "UnsecuredP2PConnection.h"

#include <iostream>

#include <boost/bind.hpp>
#include <iomanip>

UnsecuredP2PConnection::UnsecuredP2PConnection(uint32_t connectionID, io_context& io_context_, MessageQueue<ReceivedMessage>& inbox)
        : is_open_(true), connectionID_(connectionID), socket_(io_context_), inbox_(inbox) {}

UnsecuredP2PConnection::~UnsecuredP2PConnection() {
    disconnect();
}

int UnsecuredP2PConnection::connect(ip::address_v4 ip_address, uint16_t port) {
    try {
        socket_.connect(tcp::endpoint(ip_address, port));
    } catch (const boost::system::system_error& e) {
        return -1;
    }
    read();
    return 0;
}

void UnsecuredP2PConnection::disconnect() {
    std::cout << "Closing connection" << std::endl;
    if (socket_.is_open()) {
        try {
            socket_.close();
        } catch(std::exception& e) {
            std::cerr << "Could not properly shut down the connection" << std::endl;
        }
        is_open_ = false;
    }
}

void UnsecuredP2PConnection::read() {
    auto received_msg = std::make_shared<ReceivedMessage>(connectionID_);
    boost::asio::async_read(socket_,
                            boost::asio::buffer(received_msg->header()),
                            boost::bind(&UnsecuredP2PConnection::read_header,
                                        this,
                                        boost::asio::placeholders::error,
                                        received_msg));
}

void UnsecuredP2PConnection::read_header(const boost::system::error_code& e, std::shared_ptr<ReceivedMessage> received_msg) {
    if(e) {
        std::cerr << "Could not read the message header from connection: " << connectionID_ << std::endl;
        std::cerr << "Error: " << e.message() << std::endl;
    } else {
        received_msg->resizeBody();
        boost::asio::async_read(socket_,
                                boost::asio::buffer(received_msg->body()),
                                boost::bind(&UnsecuredP2PConnection::read_body,
                                            this,
                                            boost::asio::placeholders::error,
                                            received_msg));
    }
}

void UnsecuredP2PConnection::read_body(const boost::system::error_code& e, std::shared_ptr<ReceivedMessage> received_msg) {
    if(e) {
        std::cerr << "Could not read the message body from connection: " << connectionID_ << std::endl;
        for (uint8_t c : received_msg->header())
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int) c << " ";
        std::cerr << std::endl;
    }
    inbox_.push(std::move(*received_msg));
    read();

}

void UnsecuredP2PConnection::send_msg(NetworkMessage msg) {
    std::vector<boost::asio::const_buffer> combined;
    combined.push_back(boost::asio::buffer(msg.header()));
    combined.push_back(boost::asio::buffer(msg.body()));

    boost::system::error_code error;
    boost::asio::write(socket_, combined, error);
    if(error)
        std::cerr << "Error: could not send message" << std::endl;
}

bool UnsecuredP2PConnection::is_open() {
    return is_open_;
}

tcp::socket& UnsecuredP2PConnection::socket() {
    return socket_;
}

uint32_t UnsecuredP2PConnection::connectionID() {
    return connectionID_;
}
