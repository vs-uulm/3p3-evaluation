#include <cstdint>
#include <thread>
#include <list>
#include <iostream>
#include <cryptopp/oids.h>

#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../network/MessageHandler.h"
#include "../dc/DCNetwork.h"
#include "../datastruct/MessageType.h"

std::vector<Node> Nodes;

unsigned INSTANCES = 6;

void instance(int nodeID) {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    CryptoPP::AutoSeededRandomPool PRNG;
    MessageQueue<ReceivedMessage> inbox;
    MessageQueue<ReceivedMessage> inboxDCNet;
    MessageQueue<OutgoingMessage> outbox;

    io_context io_context_;
    uint16_t port = Nodes[nodeID].port();

    NetworkManager networkManager(io_context_, port, inbox);
    // Run the io_context which handles the network manager
    std::thread networkThread([&io_context_]() {
        io_context_.run();
    });

    // Add neighbors
    for(int i = 0; i < nodeID; i++) {
        uint32_t connectionID = networkManager.addNeighbor(nodeID, Nodes[i]);
        if (connectionID < 0) {
            std::cout << "Error: could not add neighbour" << std::endl;
            continue;
        }
        // Add the node as a member of the DC-Network
        std::vector<uint8_t> encodedPK(curve.GetCurve().EncodedPointSize(true));
        curve.GetCurve().EncodePoint(encodedPK.data(), Nodes[nodeID].publicKey(), true);

        OutgoingMessage helloMessage(connectionID, HelloMessage, nodeID, encodedPK);
        networkManager.sendMessage(helloMessage);
    }


    // start the message handler in a separate thread
    MessageHandler messageHandler(nodeID, inbox, inboxDCNet, outbox);
    std::thread messageHandlerThread([&]() {
        messageHandler.run();
    });

    // start the write thread
    std::thread writeThread([&]() {
        for (;;) {
            auto message = outbox.pop();
            int result = networkManager.sendMessage(*message);
            if (result < 0) {
                std::cout << "Error: could not send message" << std::endl;
            }
        }
    });

    // start the DCNetwork
    DCNetwork DCNet(nodeID, INSTANCES, inboxDCNet, outbox);
    std::thread DCThread([&]() {
        DCNet.run();
    });

    // node 0 and node 1 will always submit a message
    if (nodeID == 0 || nodeID == 1) {
        uint16_t length = PRNG.GenerateWord32(0, 128);
        std::vector<uint8_t> message(length);
        PRNG.GenerateBlock(message.data(), length);
        DCNet.submitMessage(message);
    }

    DCThread.join();
    writeThread.join();
    messageHandlerThread.join();
    networkThread.join();
}

void nodeAuthority() {
    std::unordered_map<uint32_t, Node> registeredNodes;

    MessageQueue<ReceivedMessage> inbox;
    MessageQueue<OutgoingMessage> outbox;

    io_context io_context_;
    uint16_t port = 7777;

    NetworkManager networkManager(io_context_, port, inbox);
    // Run the io_context which handles the network manager
    std::thread networkThread([&io_context_]() {
        io_context_.run();
    });


    networkThread.join();
}

int main() {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    std::list<std::thread> threads;
    CryptoPP::AutoSeededRandomPool PRNG;
    for (int i = 0; i < INSTANCES; i++) {
        CryptoPP::Integer privateKey(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
        CryptoPP::ECPPoint publicKey = curve.ExponentiateBase(privateKey);

        Node node(i, privateKey, publicKey, 5555 + i, "127.0.0.1");
        Nodes.push_back(std::move(node));
    }

    for(int i=0; i<INSTANCES; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::thread t(instance, i);
        threads.push_back(std::move(t));
    }

    for (auto it = threads.begin(); it != threads.end(); it++) {
        it->join();
    }
    return 0;
}
