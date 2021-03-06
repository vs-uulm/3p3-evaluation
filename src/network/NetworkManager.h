#ifndef THREEPP_NETWORKMANAGER_H
#define THREEPP_NETWORKMANAGER_H

#include <unordered_map>
#include "Node.h"
#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/MessageBuffer.h"
#include "UnsecuredP2PConnection.h"

using namespace boost::asio;

class NetworkManager {
public:
    NetworkManager(io_context& io_context, uint16_t port, MessageQueue<ReceivedMessage>& inbox);

    int addNeighbor(const Node& node);

    void connectToCA(const std::string& ip_address, uint16_t port);

    int sendMessage(OutgoingMessage msg);

    void start_accept();

    std::vector<uint32_t> neighbors();

    void terminate();

private:
    void accept_handler(const boost::system::error_code& e, std::shared_ptr<UnsecuredP2PConnection> connection);

    uint32_t getConnectionID();

    void storeNeighbor(uint32_t connectionID);

    void storeConnection(std::shared_ptr<UnsecuredP2PConnection> connection);

    std::mutex connectionMutex_;

    std::mutex neighborMutex_;

    io_context& io_context_;

    tcp::acceptor acceptor_;

    uint32_t maxConnectionID_;

    MessageQueue<ReceivedMessage>& inbox_;

    std::vector<uint32_t> neighbors_;

    std::shared_ptr<UnsecuredP2PConnection> centralInstance_;

    std::unordered_map<uint32_t, std::shared_ptr<UnsecuredP2PConnection>> connections_;

};


#endif //THREEPP_NETWORKMANAGER_H
