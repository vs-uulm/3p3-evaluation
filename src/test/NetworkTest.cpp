#include <iostream>
#include <cstdint>
#include <thread>
#include <list>
#include <unordered_map>

#include "../crypto/Utils.h"
#include "../network/P2PConnection.h"
#include "../datastruct/NetworkMessage.h"
#include "../network/NetworkManager.h"
#include "../network/Peer.h"
#include "../datastruct/MessageQueue.h"

std::vector<Node> Nodes;

void instance(int ID) {
    MessageQueue msg_queue;
    std::unordered_map<int, std::shared_ptr<Peer>> Peers;
    io_context network_io_context_;
    uint16_t port = Nodes[ID].port();
    NetworkManager networkManager(network_io_context_, port, msg_queue);

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

    // simulate the protocol
    std::thread message_handler([&](){
        while(true) {
            auto msg = msg_queue.pop();
            std::string body(msg->body().begin(), msg->body().end());
            std::cout << body << std::endl;
        }
    });

    // Wait until all nodes are connected
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::string server_msg = "Hello from ID " + std::to_string(ID);
    std::vector<uint8_t> msgVector(server_msg.begin(), server_msg.end());
    NetworkMessage networkMessage(0, msgVector);

    networkManager.broadcast(networkMessage);
    message_handler.join();
    network_io_thread.join();
}

int main() {
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

    return 0;
}
