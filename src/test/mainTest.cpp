#include <cstdint>
#include <thread>
#include <list>
#include <iostream>

#include "../crypto/Utils.h"
#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../network/MessageHandler.h"
#include "../dc/DCNetwork.h"

std::vector<Node> Nodes;

unsigned INSTANCES = 6;

void instance(int nodeID) {
    CryptoPP::AutoSeededRandomPool PRNG;
    MessageQueue<ReceivedMessage> inbox;
    MessageQueue<ReceivedMessage> inboxDCNet;
    MessageQueue<OutgoingMessage> outbox;

    io_context io_context_;
    uint16_t port = Nodes[nodeID].port();

    NetworkManager networkManager(io_context_, port, inbox);
    // Run the io_context which handles the network manager
    std::thread networkThread([&io_context_](){
        io_context_.run();
    });

    // Add neighbors
    for(const Node& node : Nodes) {
        if(node.nodeID() < nodeID) {
            networkManager.addNeighbor(nodeID, node);
        }
    }

    // start the message handler in a separate thread
    MessageHandler messageHandler(nodeID, inbox, inboxDCNet, outbox);
    std::thread messageHandlerThread([&]() {
        messageHandler.run();
    });

    // start the write thread
    std::thread writeThread([&]() {
        for(;;) {
            auto message = outbox.pop();
            networkManager.sendMessage(*message);
        }
    });

    // start the DCNetwork
    DCNetwork DCNet(nodeID, INSTANCES, inboxDCNet, outbox);
    std::thread DCThread([&]() {
        DCNet.run();
    });

    // the node with nodeID 0 will always submit a message
    if(nodeID == 0) {
        //uint16_t length = PRNG.GenerateWord32(0, 128);
        uint16_t length = 128;
        std::vector<uint8_t> message(length);
        PRNG.GenerateBlock(message.data(), length);
        DCNet.submitMessage(message);
    }

    DCThread.join();
    writeThread.join();
    messageHandlerThread.join();
    networkThread.join();
}

int main() {
    std::list<std::thread> threads;
    for(int i=0; i<INSTANCES; i++) {
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
