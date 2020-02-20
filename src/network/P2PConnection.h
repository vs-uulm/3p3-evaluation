#ifndef THREEPP_P2PCONNECTION_H
#define THREEPP_P2PCONNECTION_H

#include <queue>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "NetworkMessage.h"

using namespace boost::asio;
using ip::tcp;

typedef ssl::stream<tcp::socket> ssl_socket;

class P2PConnection : public boost::enable_shared_from_this<P2PConnection> {
public:
    P2PConnection(io_context& io_context_, ssl::context& ssl_context_, std::queue<std::string>& msg_queue);

    P2PConnection(io_context& io_context_, ssl::context& ssl_context_, uint16_t port, ip::address ip_address, std::queue<std::string>& msg_queue);

    ~P2PConnection();

    ssl_socket& socket();

    void async_read();

    void read_handler(const boost::system::error_code& e, std::shared_ptr<NetworkMessage> msg);

    void send_data(std::string& data);

    void read_data();

private:
    std::queue<std::string>& msg_queue;
    ssl_socket ssl_socket_;
};



#endif //THREEPP_P2PCONNECTION_H
