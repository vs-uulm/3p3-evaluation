#ifndef THREEPP_NETWORKMANAGER_H
#define THREEPP_NETWORKMANAGER_H

#include <list>
#include <boost/asio.hpp>

#include "P2PConnection.h"
#include "NetworkMessage.h"
#include "Node.h"

using namespace boost::asio;

class NetworkManager {
public:
    NetworkManager(io_context& io_context_, uint16_t port_);

    void add_neighbor(const Node& node);

    void broadcast(std::shared_ptr<NetworkMessage>& message);

    void broadcast_DC(std::shared_ptr<NetworkMessage>& message);

    void broadcast_eta(std::shared_ptr<NetworkMessage>& message, uint8_t eta);

private:
    void start_accept();

    void accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection);

    int con_ctr;

    io_context& io_context_;

    ssl::context ssl_context_;

    tcp::acceptor acceptor_;

    std::queue<std::shared_ptr<ReceivedMessage>> msg_queue;

    std::list<std::shared_ptr<P2PConnection>> connections;
};


#endif //THREEPP_NETWORKMANAGER_H
