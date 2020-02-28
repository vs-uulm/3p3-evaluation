#ifndef THREEPP_NETWORKMANAGER_H
#define THREEPP_NETWORKMANAGER_H

#include <list>
#include <boost/asio.hpp>

#include "P2PConnection.h"
#include "../datastruct/NetworkMessage.h"
#include "Node.h"
#include "../datastruct/MessageBuffer.h"

using namespace boost::asio;

class NetworkManager {
public:
    NetworkManager(io_context& io_context_, uint16_t port_, MessageQueue& msg_queue);

    int add_neighbor(const Node& node);

    void broadcast(NetworkMessage& message);

    void broadcast_DC(NetworkMessage& message);

    void broadcast_eta(NetworkMessage& message, uint8_t eta);

private:
    void start_accept();

    void accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection);

    int con_ctr;

    io_context& io_context_;

    ssl::context ssl_context_;

    tcp::acceptor acceptor_;

    MessageQueue& msg_queue_;

    MessageBuffer msg_buffer_;

    std::list<std::shared_ptr<P2PConnection>> connections_;
};


#endif //THREEPP_NETWORKMANAGER_H
