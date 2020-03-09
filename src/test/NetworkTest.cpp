#include <iostream>
#include <cstdint>
#include <thread>
#include <list>
#include <unordered_map>

#include "../crypto/Utils.h"
#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../network/Peer.h"

std::vector<Node> Nodes;
std::mutex cout_mutex;

void instance(int ID) {
    MessageQueue<NetworkMessage> msg_queue;
    std::unordered_map<int, std::shared_ptr<Peer>> Peers;
    io_context network_io_context_;
    uint16_t port = Nodes[ID].port();
    NetworkManager networkManager(network_io_context_, port, msg_queue);

    // Run the io_service
    std::thread network_io_thread([&network_io_context_](){
        network_io_context_.run();
    });

    // Add neighbors
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
            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "Instance " << ID << ": " << body << std::endl;
            }
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
    std::list<std::thread> threads;
    for(int i=0; i<10; i++) {
        Node node(i, 5555 + i, "127.0.0.1");
        Nodes.push_back(std::move(node));
        std::thread t(instance, i);
        threads.push_back(std::move(t));
    }

    for(auto it = threads.begin(); it != threads.end(); it++) {
        (*it).join();
    }
    return 0;
}
