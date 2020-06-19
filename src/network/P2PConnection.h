#ifndef THREEPP_P2PCONNECTION_H
#define THREEPP_P2PCONNECTION_H

#include <memory>
#include <queue>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/ReceivedMessage.h"
#include "../datastruct/MessageQueue.h"

using namespace boost::asio;
using ip::tcp;

typedef ssl::stream<tcp::socket> ssl_socket;

class P2PConnection {
public:
    P2PConnection(uint32_t connectionID, io_context& io_context_, ssl::context& ssl_context_, MessageQueue<ReceivedMessage>& inbox);

    ~P2PConnection();

    int connect(ip::address_v4 ip_address, uint16_t port);

    void disconnect();

    void async_handshake();

    void send(NetworkMessage msg);

    void async_send(bool handler);

    bool is_open();

    ssl_socket& socket();

    uint32_t connectionID();

private:
    void handshake_handler(const boost::system::error_code& e);

    void read();

    std::mutex mutex_;

    bool is_open_;

    bool sending_;

    uint32_t connectionID_;

    ssl_socket ssl_socket_;

    MessageQueue<ReceivedMessage>& inbox_;

    MessageQueue<NetworkMessage> outbox_;
};



#endif //THREEPP_P2PCONNECTION_H
