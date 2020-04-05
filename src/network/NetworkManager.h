#ifndef THREEPP_NETWORKMANAGER_H
#define THREEPP_NETWORKMANAGER_H

#include <list>
#include <unordered_map>
#include <boost/asio.hpp>

#include "P2PConnection.h"
#include "Node.h"
#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/MessageBuffer.h"

using namespace boost::asio;

class NetworkManager {
public:
    NetworkManager(io_context& io_context_, uint16_t port_, MessageQueue<ReceivedMessage>& inbox);

    int addNeighbor(uint32_t nodeID, const Node& node);

    int sendMessage(OutgoingMessage& msg);
private:
    void start_accept();

    void accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection);

    std::mutex mutex_;

    io_context& io_context_;

    ssl::context ssl_context_;

    tcp::acceptor acceptor_;

    uint32_t maxConnectionID_;

    MessageQueue<ReceivedMessage>& inbox_;

    std::unordered_map<uint32_t, std::shared_ptr<P2PConnection>> connections_;
};


#endif //THREEPP_NETWORKMANAGER_H
