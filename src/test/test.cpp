#include <iostream>
#include <cstdint>
#include <thread>

#include "../network/p2p_connection.h"
#include "../network/peer_handler.h"

void connect_task() {
    uint16_t port = 7777;
    ip::address ip_address = ip::address::from_string("127.0.0.1");
    io_context io_context_;
    ssl::context ssl_context_(ssl::context::sslv23);
    ssl_context_.set_options(ssl::context::default_workarounds |
                             ssl::context::no_sslv2 |
                             ssl::context::no_sslv3);

    p2p_connection connection(io_context_, ssl_context_, port, ip_address);
    connection.socket().handshake(ssl::stream_base::client);

    std::string msg = "Hello from Client!";
    connection.send_data(msg);
}

void server_task() {
    io_context io_context_;
    peer_handler p2p_handler_(io_context_, 7777);
    io_context_.run();
}

int main() {
    uint16_t port = 7777;
    ip::address ip_address = ip::address::from_string("127.0.0.1");

    std::thread server(server_task);
    std::thread client1(connect_task);
    std::thread client2(connect_task);
    client1.join();
    server.join();
    return 0;
}
