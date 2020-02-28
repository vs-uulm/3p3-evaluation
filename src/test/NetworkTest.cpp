#include <iostream>
#include <cstdint>
#include <thread>
#include <list>
#include <unordered_map>

#include "../crypto/Utils.h"
#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../network/Peer.h"
#include "../datastruct/MessageBuffer.h"

std::vector<Node> Nodes;
std::mutex cout_mutex;

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

    /*
    MessageBuffer buffer(3);

    std::vector<uint8_t> body1 = {0,0,0,1};
    std::vector<uint8_t> body2 = {0,0,0,2};
    std::vector<uint8_t> body3 = {0,0,0,3};
    std::vector<uint8_t> body4 = {0,0,0,4};
    std::vector<uint8_t> body5 = {0,0,0,5};

    ReceivedMessage msg1(1);
    ReceivedMessage msg2(2);
    ReceivedMessage msg3(3);
    ReceivedMessage msg4(4);
    ReceivedMessage msg5(5);

    msg1.header()[3] = 4;
    msg1.resize_body();
    msg1.body() = body1;

    msg2.header()[3] = 4;
    msg2.resize_body();
    msg2.body() = body2;

    msg3.header()[3] = 4;
    msg3.resize_body();
    msg3.body() = body3;

    msg4.header()[3] = 4;
    msg4.resize_body();
    msg4.body() = body5;

    msg5.header()[3] = 4;
    msg5.resize_body();
    msg5.body() = body5;

    buffer.add(msg1);
    buffer.add(msg2);
    buffer.add(msg3);
    buffer.add(msg4);
    buffer.add(msg5);


    std::shared_ptr<BufferedMessage> buff_msg = buffer.contains(msg3);
    std::cout << "Sender List: " << buff_msg->sender_list().size() << std::endl;
    if(buff_msg)
        std::cout << "msg1 found" << std::endl;
    else
        std::cout << "msg1 not found" << std::endl;

    buff_msg = buffer.contains(msg3);
    std::cout << "Sender List: " << buff_msg->sender_list().size() << std::endl;
    if(buff_msg)
        std::cout << "msg3 found" << std::endl;
    else
        std::cout << "msg3 not found" << std::endl;

    */

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
