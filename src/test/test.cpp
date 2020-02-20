#include <iostream>
#include <cstdint>
#include <thread>
#include <list>

#include "../network/P2PConnection.h"
#include "../network/NetworkMessage.h"

std::queue<std::string> msg_queue;
std::list<std::shared_ptr<P2PConnection>> p2p_connections;

void connect_task() {
    uint16_t port = 7777;
    ip::address ip_address = ip::address::from_string("127.0.0.1");
    io_context io_context_;
    ssl::context ssl_context_(ssl::context::sslv23);
    ssl_context_.set_options(ssl::context::default_workarounds |
                             ssl::context::no_sslv2 |
                             ssl::context::no_sslv3);

    P2PConnection connection(io_context_, ssl_context_, port, ip_address, msg_queue);
    std::cout << "Client connected" << std::endl;
    std::string msg = "Hello from Client!";
    connection.send_data(msg);
    connection.read_data();
    std::cout << "Finished reading" << std::endl;
}

void server_task() {
    io_context io_context_;
    ssl::context ssl_context_(ssl::context::sslv23);
    ssl_context_.set_options(ssl::context::default_workarounds |
                             ssl::context::no_sslv2 |
                             ssl::context::no_sslv3);
    ssl_context_.use_private_key_file("../cert/private.pem", ssl::context::pem);
    ssl_context_.use_certificate_chain_file("../cert/server_cert.pem");

    tcp::acceptor acceptor_(io_context_, tcp::endpoint(tcp::v4(), 7777));
    for(;;) {
        std::shared_ptr<P2PConnection> new_connection = std::make_shared<P2PConnection>(io_context_, ssl_context_, msg_queue);
        p2p_connections.push_back(new_connection);
        acceptor_.accept(new_connection->socket().lowest_layer());
        new_connection->socket().handshake(ssl::stream_base::server);
        new_connection->read_data();
        std::string msg = "Hello from Server!";
        new_connection->send_data(msg);
    }
}

int main() {
    uint16_t port = 7777;
    ip::address ip_address = ip::address::from_string("127.0.0.1");
    std::thread server(server_task);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    NetworkMessage msg =
    /*
    std::thread client1(connect_task);
    std::thread client2(connect_task);
    std::thread client3(connect_task);

    client1.join();
    client2.join();
    client3.join();
    */
    server.detach();
    return 0;
}
