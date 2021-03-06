#ifndef THREEPP_SECUREDNETWORKMANAGER_H
#define THREEPP_SECUREDNETWORKMANAGER_H

#include <list>
#include <unordered_map>
#include <boost/asio.hpp>

#include "P2PConnection.h"
#include "Node.h"
#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/MessageBuffer.h"

using namespace boost::asio;

class SecuredNetworkManager {
public:
    SecuredNetworkManager(io_context& io_context_, uint16_t port_, MessageQueue<ReceivedMessage>& inbox);

    int addNeighbor(const Node& node);

    void connectToCA(const std::string& ip_address, uint16_t port);

    int sendMessage(OutgoingMessage msg);

    std::vector<uint32_t> neighbors();

    void start_accept();

    void terminate();

private:
    void accept_handler(const boost::system::error_code& e, std::shared_ptr<P2PConnection> connection);

    uint32_t getConnectionID();

    void storeNeighbor(uint32_t connectionID);

    void storeConnection(std::shared_ptr<P2PConnection> connection);

    std::mutex connectionMutex_;

    std::mutex neighborMutex_;

    io_context& io_context_;

    ssl::context ssl_context_;

    tcp::acceptor acceptor_;

    uint32_t maxConnectionID_;

    MessageQueue<ReceivedMessage>& inbox_;

    std::vector<uint32_t> neighbors_;

    std::shared_ptr<P2PConnection> centralInstance_;

    std::unordered_map<uint32_t, std::shared_ptr<P2PConnection>> connections_;

};


#endif //THREEPP_SECUREDNETWORKMANAGER_H
