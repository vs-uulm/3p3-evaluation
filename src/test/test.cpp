#include <iostream>
#include <cstdint>
#include <thread>
#include <list>

#include "../network/P2PConnection.h"
#include "../network/NetworkMessage.h"
#include "../network/NetworkManager.h"

std::queue<std::shared_ptr<NetworkMessage>> msg_queue;
std::list<std::shared_ptr<P2PConnection>> p2p_connections;

void connect_task() {
    uint16_t port = 7777;
    ip::address ip_address = ip::address::from_string("127.0.0.1");
    io_context io_context_;
    ssl::context ssl_context_(ssl::context::sslv23);
    ssl_context_.set_options(ssl::context::default_workarounds |
                             ssl::context::no_sslv2 |
                             ssl::context::no_sslv3);

    auto connection = std::make_shared<P2PConnection>(io_context_, ssl_context_, port, ip_address, msg_queue);

    // keep the connection alive
    p2p_connections.push_back(connection);

    std::string msg = "Msg!";
    connection->send_data(msg);

    connection->read_data();
}

int main() {
    io_context io_context_;
    uint16_t port = 7777;
    NetworkManager networkManager(io_context_, port);

    // Run the io_service
    std::thread([&io_context_](){
        io_context_.run();
    }).detach();

    std::this_thread::sleep_for(std::chrono::seconds(1));


    std::thread client1(connect_task);
    std::thread client2(connect_task);
    std::thread client3(connect_task);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::string msg = "Test Message";
    networkManager.broadcast(msg);
    client1.join();
    client2.join();
    client3.join();
    return 0;
}
