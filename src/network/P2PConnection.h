#ifndef THREEPP_P2PCONNECTION_H
#define THREEPP_P2PCONNECTION_H

#include <queue>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "NetworkMessage.h"
#include "ReceivedMessage.h"

using namespace boost::asio;
using ip::tcp;

typedef ssl::stream<tcp::socket> ssl_socket;

class P2PConnection {
public:
    P2PConnection(io_context& io_context_, ssl::context& ssl_context_,
            std::queue<std::shared_ptr<ReceivedMessage>>& msg_queue);

    P2PConnection(io_context& io_context_, ssl::context& ssl_context_, uint16_t port,
            ip::address ip_address, std::queue<std::shared_ptr<ReceivedMessage>>& msg_queue);

    ~P2PConnection();

    ssl_socket& socket();

    void connect(ip::address ip_address, uint16_t port);

    void async_handshake();

    void send_msg(NetworkMessage& msg);

private:
    void connect_handler(const boost::system::error_code& e);

    void handshake_handler(const boost::system::error_code& e);

    void async_read();

    void read_header(const boost::system::error_code& e, std::shared_ptr<ReceivedMessage> msg);

    void read_body(const boost::system::error_code& e, std::shared_ptr<ReceivedMessage> msg);

    uint32_t peerID;

    ssl_socket ssl_socket_;

    std::queue<std::shared_ptr<ReceivedMessage>>& msg_queue;
};



#endif //THREEPP_P2PCONNECTION_H
