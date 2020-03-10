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
    NetworkManager(io_context& io_context_, uint16_t port_, MessageQueue<ReceivedMessage>& inbox);

    uint32_t addNeighbor(uint32_t nodeID, const Node& node);

    void directMessage(uint32_t connectionID, NetworkMessage& msg);

    void floodAndPrune(NetworkMessage& msg);

private:
    void start_accept();

    void accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection);

    std::mutex mutex_;

    io_context& io_context_;

    ssl::context ssl_context_;

    tcp::acceptor acceptor_;

    uint32_t maxConnectionID;

    MessageQueue<ReceivedMessage>& inbox_;

    std::list<std::shared_ptr<P2PConnection>> connections_;
};


#endif //THREEPP_NETWORKMANAGER_H
