#include "UnsecuredP2PConnection.h"
#include "../datastruct/MessageType.h"

#include <iostream>
#include <boost/bind.hpp>
#include <iomanip>

UnsecuredP2PConnection::UnsecuredP2PConnection(uint32_t connectionID, io_context &io_context_,
                                               MessageQueue<ReceivedMessage> &inbox)
        : is_open_(true), sending_(false), connectionID_(connectionID), socket_(io_context_), inbox_(inbox) {}

UnsecuredP2PConnection::~UnsecuredP2PConnection() {
    disconnect();
}

int UnsecuredP2PConnection::connect(ip::address_v4 ip_address, uint16_t port) {
    try {
        socket_.connect(tcp::endpoint(ip_address, port));
    } catch (const boost::system::system_error &e) {
        return -1;
    }
    read();
    return 0;
}

void UnsecuredP2PConnection::disconnect() {
    if (socket_.is_open()) {
        boost::system::error_code ec;
        try {
            socket_.close(ec);
        } catch (std::exception &e) {
            std::cerr << "Could not properly shut down the connection" << std::endl;
            std::cerr << e.what() << std::endl;
        }
        is_open_ = false;
    }
}

void UnsecuredP2PConnection::read() {
    auto received_msg = std::make_shared<ReceivedMessage>(connectionID_);
    // read the message header
    boost::asio::async_read(socket_,
                            boost::asio::buffer(received_msg->header()),
                            [this, received_msg](const boost::system::error_code &error, size_t) {
                                if (!error) {
                                    received_msg->resizeBody();
                                    // read the
                                    boost::asio::async_read(socket_,
                                                            boost::asio::buffer(received_msg->body()),
                                                            [this, received_msg](const boost::system::error_code &error,
                                                                                 size_t) {
                                                                if (!error) {
                                                                    received_msg->timestamp(std::chrono::system_clock::now());
                                                                    inbox_.push(std::move(*received_msg));
                                                                    read();
                                                                } else if (error == boost::asio::error::eof
                                                                    || error == boost::asio::error::operation_aborted) {
                                                                    return;
                                                                } else {
                                                                    std::cerr << "Error: " << error.message()
                                                                              << std::endl;
                                                                }
                                                            });
                                } else if (error == boost::asio::error::eof ||
                                           error == boost::asio::error::operation_aborted) {
                                    return;
                                } else {
                                    std::cerr << "Error: " << error.message() << std::endl;
                                }
    });
}

void UnsecuredP2PConnection::send(NetworkMessage msg) {
    outbox_.push(std::move(msg));
    async_send(false);
}

void UnsecuredP2PConnection::async_send(bool handler) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (sending_ && !handler)
            return;

        if (outbox_.empty()) {
            sending_ = false;
            return;
        } else if(!sending_) {
            sending_ = true;
        }
    }
    NetworkMessage msg = outbox_.pop();
    std::vector<boost::asio::const_buffer> combined;
    combined.push_back(boost::asio::buffer(msg.header()));
    combined.push_back(boost::asio::buffer(msg.body()));

    boost::asio::async_write(socket_,
                             combined,
                             [this](const boost::system::error_code &error, size_t) {
                                 if (error) {
                                     std::cout << "Write error" << std::endl;
                                 }
                                 async_send(true);
                             });
}

bool UnsecuredP2PConnection::is_open() {
    return is_open_;
}

tcp::socket &UnsecuredP2PConnection::socket() {
    return socket_;
}

uint32_t UnsecuredP2PConnection::connectionID() {
    return connectionID_;
}
