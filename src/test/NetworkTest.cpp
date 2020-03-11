#include <cstdint>
#include <thread>
#include <list>

#include "../crypto/Utils.h"
#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../network/MessageHandler.h"
#include "../threePP/DCNetwork.h"

std::vector<Node> Nodes;

void instance(int ID) {
    MessageQueue<ReceivedMessage> inbox;
    MessageQueue<ReceivedMessage> inboxDCNet;
    MessageQueue<OutgoingMessage> outbox;

    io_context io_context_;
    uint16_t port = Nodes[ID].port();

    NetworkManager networkManager(io_context_, port, inbox);
    MessageHandler messageHandler(ID, inbox, inboxDCNet, outbox);
    DCNetwork DCNet( ID, 4, inboxDCNet, outbox);

    // Run the io_context
    std::thread networkThread([&io_context_](){
        io_context_.run();
    });

    // Add neighbors
    for(const Node& node : Nodes) {
        if(node.nodeID() < ID) {
            networkManager.addNeighbor(ID, node);
        }
    }

    // start the message handler in a separate thread
    std::thread messageHandlerThread([&]() {
        messageHandler.run();
    });

    // start the DCNetwork
    std::thread DCThread([&]() {
        DCNet.run();
    });

    // Wait until all nodes are connected
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::string server_msg = "Hello from ID " + std::to_string(ID);
    std::vector<uint8_t> msgVector(server_msg.begin(), server_msg.end());
    OutgoingMessage networkMessage(-1, 0, msgVector);

    //networkManager.initFaP(networkMessage);
    DCThread.join();
    messageHandlerThread.join();
    networkThread.join();
}

int main() {
    std::list<std::thread> threads;
    for(int i=0; i<4; i++) {
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
