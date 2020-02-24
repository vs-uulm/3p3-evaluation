#include <iostream>
#include <cstdint>
#include <thread>
#include <list>
#include <unordered_map>

#include "../network/P2PConnection.h"
#include "../network/NetworkMessage.h"
#include "../network/NetworkManager.h"

std::unordered_map<int, std::shared_ptr<Node>> Nodes;

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
    P2PConnection* connection = new P2PConnection(io_context_, ssl_context_, port, ip_address, msg_queue);
    std::string msg = "Client Message!";
    std::vector<uint8_t> msgVector(msg.begin(), msg.end());
    NetworkMessage networkMessage(0, msgVector);
    connection->send_msg(networkMessage);
    std::cout << "Client msg sent" << std::endl;
    //connection->read_data();
}

void instance(int ID) {
    io_context* io_context_ = new io_context;
    uint16_t port = Nodes[ID]->get_port();
    NetworkManager* networkManager = new NetworkManager(*io_context_, port);
    // Run the io_service

    std::thread([&io_context_](){
        std::cout << "IO Service running" << std::endl;
        io_context_->run();
    }).detach();
}

int main() {
    /*
    std::string testMsg = "This is a test message";
    std::vector<uint8_t> msgVector(testMsg.begin(), testMsg.end());

    std::vector<uint8_t> testHeader;
    NetworkMessage msg;
    //networkMessage.header() = testHeader;
    // TODO fix this
    msg.header().shrink_to_fit();
    std::cout << "Standard Size: " << msg.header().size() << std::endl;
    msg.header().resize(10);
    std::cout << "Resized: " << msg.header().size() << std::endl;
     */
    /*
    std::shared_ptr<Node> node1 = std::make_shared<Node>(0, 7777, "127.0.0.1");
    std::shared_ptr<Node> node2 = std::make_shared<Node>(1, 8888, "127.0.0.1");
    std::shared_ptr<Node> node3 = std::make_shared<Node>(2, 9999, "127.0.0.1");

    Nodes.insert({0, std::move(node1)});
    Nodes.insert({1, std::move(node2)});
    Nodes.insert({2, std::move(node3)});

    std::thread instance1(instance, 0);
    instance1.detach();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::thread client1(connect_task);
    //std::thread instance2(instance, 1);
    //std::thread instance3(instance, 2);
    client1.join();
    //instance1.join();
    //instance2.join();
    //instance3.join();
    */
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
    return 0;
}
