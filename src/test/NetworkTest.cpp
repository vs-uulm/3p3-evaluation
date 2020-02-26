#include <iostream>
#include <cstdint>
#include <thread>
#include <list>

#include "../crypto/Utils.h"
#include "../network/P2PConnection.h"
#include "../datastruct/NetworkMessage.h"
#include "../network/NetworkManager.h"

#include "TestData.h"
#include "../network/Peer.h"
#include "../datastruct/MessageQueue.h"

std::vector<Node> Nodes;

/*
void client_task() {
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
*/

void instance(int ID) {
    std::unordered_map<int, std::shared_ptr<Peer>> Peers;
    io_context network_io_context_;
    uint16_t port = Nodes[ID].port();
    NetworkManager networkManager(network_io_context_, port);

    // Run the io_service

    std::thread network_io_thread([&network_io_context_](){
        network_io_context_.run();
    });


    // Adding nodes
    for(const Node& node : Nodes) {
        if(node.nodeID() < ID) {
            networkManager.add_neighbor(node);
        }
    }

    // Wait until all nodes are connected
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::string server_msg = "Hello from ID " + std::to_string(ID);
    std::vector<uint8_t> msgVector(server_msg.begin(), server_msg.end());
    NetworkMessage networkMessage(0, msgVector);

    networkManager.broadcast(networkMessage);

    network_io_thread.join();
}

int main() {
    std::string msg_body = "Test Message";
    std::vector<uint8_t> testData(msg_body.begin(), msg_body.end());
    NetworkMessage msg1(0, testData);
    NetworkMessage msg2(1, testData);
    NetworkMessage msg3(2, testData);

    MessageQueue msg_queue;
    msg_queue.push(std::make_shared<NetworkMessage>(msg2));
    auto msg_ptr = msg_queue.pop();
    if(msg_ptr != nullptr) {
        std::string result(msg_ptr->body().begin(), msg_ptr->body().end());
        std::cout << result << std::endl;
    }
    /*
    Node node1(0, 7777, "127.0.0.1");
    Node node2(1, 8888, "127.0.0.1");
    Node node3(2, 9999, "127.0.0.1");

    Nodes.push_back(std::move(node1));
    Nodes.push_back(std::move(node2));
    Nodes.push_back(std::move(node3));

    std::thread instance1(instance, 0);
    std::thread instance2(instance, 1);
    std::thread instance3(instance, 2);

    instance1.join();
    instance2.join();
    instance3.join();
     */

    //std::thread client1(connect_task);
    //std::thread client2(connect_task);
    //std::thread client3(connect_task);

    //client1.join();
    //client2.join();
    //client3.join();

    return 0;
}
