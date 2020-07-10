#ifndef THREEPP_UNSECUREDP2PCONNECTION_H
#define THREEPP_UNSECUREDP2PCONNECTION_H

#include <cstdint>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/ReceivedMessage.h"
#include "../datastruct/MessageQueue.h"

using namespace boost::asio;
using ip::tcp;

class UnsecuredP2PConnection : public boost::enable_shared_from_this<UnsecuredP2PConnection> {
public:
    UnsecuredP2PConnection(uint32_t connectionID, io_context &io_context_, MessageQueue<ReceivedMessage>& inbox);

    ~UnsecuredP2PConnection();

    int connect(ip::address_v4 ip_address, uint16_t port);

    void disconnect();

    void send(NetworkMessage msg);

    void async_send(bool handler);

    bool is_open();

    tcp::socket& socket();

    uint32_t connectionID();

    void read();

private:
    bool is_open_;

    bool sending_;

    std::mutex mutex_;

    uint32_t connectionID_;

    tcp::socket socket_;

    MessageQueue<ReceivedMessage>& inbox_;

    MessageQueue<NetworkMessage> outbox_;
};


#endif //THREEPP_UNSECUREDP2PCONNECTION_H
