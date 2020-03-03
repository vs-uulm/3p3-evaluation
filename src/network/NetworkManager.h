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
    NetworkManager(io_context& io_context_, uint16_t port_, MessageQueue<NetworkMessage>& msg_queue);

    int add_neighbor(const Node& node);

    void send_msg(NetworkMessage& msg, uint32_t connectionID);

    void broadcast(NetworkMessage& message);

    void broadcast_DC(NetworkMessage& message);

    void broadcast_eta(NetworkMessage& message, uint8_t eta);

    void flood_and_prune(NetworkMessage& message);

private:
    void start_accept();

    void accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection);

    int connection_counter;

    io_context& io_context_;

    ssl::context ssl_context_;

    tcp::acceptor acceptor_;

    MessageBuffer msg_buffer_;

    MessageQueue<NetworkMessage>& msg_queue_;

    std::list<std::shared_ptr<P2PConnection>> connections_;
};


#endif //THREEPP_NETWORKMANAGER_H
