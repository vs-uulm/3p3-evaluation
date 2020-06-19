#include "P2PConnection.h"

#include <iostream>

#include <boost/bind.hpp>
#include <iomanip>


P2PConnection::P2PConnection(uint32_t connectionID, io_context &io_context_, ssl::context& ssl_context,
                             MessageQueue<ReceivedMessage> &inbox)
        : is_open_(false), sending_(false), connectionID_(connectionID), ssl_socket_(io_context_, ssl_context), inbox_(inbox) {

}


P2PConnection::~P2PConnection() {
    disconnect();
}

int P2PConnection::connect(ip::address_v4 ip_address, uint16_t port) {
    try {
        ssl_socket_.lowest_layer().connect(tcp::endpoint(ip_address, port));
        ssl_socket_.handshake(ssl::stream_base::client);
    } catch (const boost::system::system_error &e) {
        return -1;
    }
    is_open_ = true;
    read();
    return 0;
}

void P2PConnection::disconnect() {
    std::cout << "Closing connection" << std::endl;
    if (ssl_socket_.lowest_layer().is_open()) {
        try {
            ssl_socket_.shutdown();
            ssl_socket_.lowest_layer().shutdown(socket_base::shutdown_send);
            ssl_socket_.lowest_layer().close();
        } catch (std::exception &e) {
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

void P2PConnection::handshake_handler(const boost::system::error_code &e) {
    if (e) {
        std::cerr << "Handshake Error:" << e.message() << std::endl;
    } else {
        read();
        is_open_ = true;
    }
}


void P2PConnection::read() {
    auto received_msg = std::make_shared<ReceivedMessage>(connectionID_);
    // read the message header
    boost::asio::async_read(ssl_socket_,
                            boost::asio::buffer(received_msg->header()),
                            [this, received_msg](const boost::system::error_code &error, size_t) {
                                if (!error) {
                                    received_msg->resizeBody();
                                    // read the body
                                    boost::asio::async_read(ssl_socket_,
                                                            boost::asio::buffer(received_msg->body()),
                                                            [this, received_msg](const boost::system::error_code &error,
                                                                        size_t) {
                                                                if (!error) {
                                                                    inbox_.push(std::move(*received_msg));
                                                                    read();
                                                                } else if (error == boost::asio::error::eof || error == boost::asio::error::operation_aborted) {
                                                                    return;
                                                                } else {
                                                                    std::cerr << "Error: could not read the body" << std::endl;
                                                                    read();
                                                                }
                                                            });
                                } else if (error == boost::asio::error::eof ||
                                           error == boost::asio::error::operation_aborted) {
                                    return;
                                } else {
                                    std::cerr << "Error: could not read the header" << std::endl;
                                    read();
                                }
    });
}

void P2PConnection::send(NetworkMessage msg) {
    outbox_.push(std::move(msg));
    async_send(false);
}

void P2PConnection::async_send(bool handler) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (sending_ && !handler)
            return;

        if (outbox_.empty()) {
            sending_ = false;
            return;
        } else if (!sending_) {
            sending_ = true;
        }
    }
    std::shared_ptr<NetworkMessage> msg_ptr = std::make_shared<NetworkMessage>(outbox_.pop());
    boost::asio::async_write(ssl_socket_,
                             boost::asio::buffer(msg_ptr->header()),
                             [this, msg_ptr](const boost::system::error_code &error, size_t) {
                                 if (error) {
                                     std::cerr << "Error: could no send the message" << std::endl;
                                 }
                                 boost::asio::async_write(ssl_socket_,
                                                          boost::asio::buffer(msg_ptr->body()),
                                                          [this, msg_ptr](const boost::system::error_code &error, size_t) {
                                                              if (error) {
                                                                  std::cerr << "Error: could no send the message" << std::endl;
                                                              }
                                                              async_send(true);
                                 });
    });
}

bool P2PConnection::is_open() {
    return is_open_;
}


ssl_socket &P2PConnection::socket() {
    return ssl_socket_;
}

uint32_t P2PConnection::connectionID() {
    return connectionID_;
}
