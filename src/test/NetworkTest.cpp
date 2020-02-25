#include <iostream>
#include <cstdint>
#include <thread>
#include <list>

#include "../crypto/Utils.h"
#include "../network/P2PConnection.h"
#include "../network/NetworkMessage.h"
#include "../network/NetworkManager.h"

#include "TestData.h"

std::vector<Node> Nodes;

void connect_task() {
    uint16_t port = 7777;
    ip::address ip_address = ip::address::from_string("127.0.0.1");
    io_context io_context_;
    ssl::context ssl_context_(ssl::context::sslv23);
    ssl_context_.set_options(ssl::context::default_workarounds |
                             ssl::context::no_sslv2 |
                             ssl::context::no_sslv3);

    std::queue<std::shared_ptr<ReceivedMessage>> msg_queue;
    // use a raw pointer to keep the connection alive
    P2PConnection* connection = new P2PConnection(io_context_, ssl_context_, msg_queue);
    int retry_count = 3;
    while(retry_count > 0) {
        if(connection->connect(ip_address, port) == 0)
            break;
        retry_count--;
        std::cout << "Connection refused: retry in 1 second" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::thread io_thread([&io_context_](){
        io_context_.run();
        std::cout << "IO thread has finished" << std::endl;
    });

    std::string msg = "Client Message!";
    std::vector<uint8_t> msgVector(msg.begin(), msg.end());
    NetworkMessage networkMessage(0, msgVector);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    connection->send_msg(networkMessage);
    std::cout << "Client msg sent" << std::endl;

    io_thread.join();
}

void instance(int ID) {
    io_context network_io_context_;
    uint16_t port = Nodes[ID].port();
    NetworkManager* networkManager = new NetworkManager(network_io_context_, port);

    // Run the io_service
    std::thread network_io_thread([&network_io_context_](){
        network_io_context_.run();
        std::cout << "Finished" << std::endl;
    });

    for(const Node& node : Nodes) {
        if(node.nodeID() < ID) {
            int result = networkManager->add_neighbor(node);
            std::cout << "Result: " << result << std::endl;
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    std::string server_msg = "Hello from ID " + std::to_string(ID);
    std::vector<uint8_t> msgVector(server_msg.begin(), server_msg.end());
    NetworkMessage networkMessage(0, msgVector);
    std::cout << "Broadcasting" << std::endl;
    networkManager->broadcast(networkMessage);

    network_io_thread.join();
}

int main() {
    Node node1(0, 7777, "127.0.0.1");
    Node node2(1, 8888, "127.0.0.1");
    Node node3(2, 9999, "127.0.0.1");

    Nodes.push_back(std::move(node1));
    Nodes.push_back(std::move(node2));
    //Nodes.push_back(std::move(node3));

    std::thread instance1(instance, 0);
    //std::thread instance2(instance, 1);
    //std::thread instance3(instance, 2);
    std::thread client1(connect_task);
    //std::thread client2(connect_task);
    //std::thread client3(connect_task);
    instance1.join();
    client1.join();
    //client2.join();
    //client3.join();
    //instance2.join();
    //instance3.join();

    /*
    io_context io_context_;
    uint16_t port = 7777;
    NetworkManager networkManager(io_context_, port);

    // Run the io_service
    std::thread([&io_context_](){
        io_context_.run();
    }).detach();

    std::thread client1(connect_task);
    //std::thread client2(connect_task);
    //std::thread client3(connect_task);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::string msg = "Test Message";

    //networkManager.broadcast(msg);
    client1.join();
    //client2.join();
    //client3.join();
     */
    return 0;
}
