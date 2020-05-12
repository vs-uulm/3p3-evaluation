#ifndef THREEPP_UNSECUREDNETWORKMANAGER_H
#define THREEPP_UNSECUREDNETWORKMANAGER_H

#include <unordered_map>
#include "Node.h"
#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/MessageBuffer.h"
#include "UnsecuredP2PConnection.h"

using namespace boost::asio;

class UnsecuredNetworkManager {
public:
    UnsecuredNetworkManager(io_context& io_context, uint16_t port, MessageQueue<ReceivedMessage>& inbox);

    int addNeighbor(const Node& node);

    int connectToCA(const std::string& ip_address, uint16_t port);

    int sendMessage(OutgoingMessage msg);

    void start_accept();

    std::vector<uint32_t> neighbors();

private:
    void accept_handler(const boost::system::error_code& e, std::shared_ptr<UnsecuredP2PConnection> connection);

    uint32_t getConnectionID();

    std::mutex mutex_;

    io_context& io_context_;

    tcp::acceptor acceptor_;

    uint32_t maxConnectionID_;

    MessageQueue<ReceivedMessage>& inbox_;

    std::vector<uint32_t> neighbors_;

    std::unordered_map<uint32_t, std::shared_ptr<UnsecuredP2PConnection>> connections_;

};


#endif //THREEPP_UNSECUREDNETWORKMANAGER_H
