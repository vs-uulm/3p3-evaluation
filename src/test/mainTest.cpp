#include <cstdint>
#include <thread>
#include <list>
#include <iostream>
#include <cryptopp/oids.h>
#include <iomanip>

#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../network/MessageHandler.h"
#include "../dc/DCNetwork.h"
#include "../datastruct/MessageType.h"

std::mutex cout_mutex;

const uint32_t INSTANCES = 6;

void instance(int ID) {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    CryptoPP::AutoSeededRandomPool PRNG;
    MessageQueue<ReceivedMessage> inbox;
    MessageQueue<ReceivedMessage> inboxDCNet;
    MessageQueue<OutgoingMessage> outbox;

    io_context io_context_;
    uint16_t port_ = 5555 + ID;
    ip::address_v4 ip_address(ip::address_v4::from_string("127.0.0.1"));

    NetworkManager networkManager(io_context_, port_, inbox);
    // Run the io_context which handles the network manager
    std::thread networkThread1([&io_context_]() {
        io_context_.run();
    });

    // connect to the central node authority
    int CAConnectionID = networkManager.connectToCA("127.0.0.1", 7777);
    if(CAConnectionID < 0) {
        std::cout << "Error: could not connect to the central authority" << std::endl;
    }

    // generate an EC keypair
    CryptoPP::Integer privateKey(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
    CryptoPP::ECPPoint publicKey = curve.ExponentiateBase(privateKey);

    std::vector<uint8_t> messageBody(6 + curve.GetCurve().EncodedPointSize(true));
    // set the port
    messageBody[0] = (port_ & 0xFF00) >> 8;
    messageBody[1] = (port_ & 0x00FF);

    std::array<uint8_t, 4> encodedIP = ip_address.to_bytes();
    std::copy(&encodedIP[0], &encodedIP[5], &messageBody[2]);

    // set the compressed public key
    curve.GetCurve().EncodePoint(messageBody.data() + 6, publicKey, true);

    OutgoingMessage registerMessage(CAConnectionID, RegisterMessage, SELF, messageBody);
    networkManager.sendMessage(registerMessage);

    auto registerResponse = inbox.pop();
    if(registerResponse.msgType() != RegisterResponse)
        return;

    // decode the received nodeID
    uint32_t nodeID_ = ((registerResponse.body()[0]) << 24) | (registerResponse.body()[1] << 16)
                            | (registerResponse.body()[2] << 8) | registerResponse.body()[3];

    // wait until the nodeInfo message arrives
    auto nodeInfo = inbox.pop();
    if(nodeInfo.msgType() != NodeInfoMessage)
        return;

    // First determine the number of nodes received
    uint32_t numNodes = (nodeInfo.body()[0] << 24) | (nodeInfo.body()[1] << 16) | (nodeInfo.body()[2] << 8) | (nodeInfo.body()[3]);

    std::unordered_map<uint32_t, Node> neighbors;
    neighbors.reserve(numNodes);

    // decode the submitted info
    size_t infoSize = 10 + curve.GetCurve().EncodedPointSize(true);
    for(uint32_t i = 0, offset = 4; i < numNodes; i++, offset += infoSize) {
        // extract the nodeID
        uint32_t nodeID = (nodeInfo.body()[offset] << 24) | (nodeInfo.body()[offset+1] << 16)
                            | (nodeInfo.body()[offset+2] << 8) | (nodeInfo.body()[offset+3]);

        // extract the port
        uint16_t port = (nodeInfo.body()[offset+4] << 8) | nodeInfo.body()[offset+5];

        // extract the IP adddress
        std::array<uint8_t, 4> decodedIP;
        std::copy(&nodeInfo.body()[offset+6], &nodeInfo.body()[offset+10], &decodedIP[0]);
        ip::address_v4 ip_address(decodedIP);

        // decode the public key
        CryptoPP::ECPPoint publicKey;
        curve.GetCurve().DecodePoint(publicKey, &nodeInfo.body()[offset+10], curve.GetCurve().EncodedPointSize(true));

        Node neighbor(nodeID, publicKey, port, ip_address);
        neighbors.insert(std::pair(nodeID, neighbor));
    }

    // wait until all nodes have received the information
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Add neighbors
    for(int i = 0; i < nodeID_; i++) {
        uint32_t connectionID = networkManager.addNeighbor(neighbors[i]);
        if (connectionID < 0) {
            std::cout << "Error: could not add neighbour" << std::endl;
            continue;
        }
        // Add the node as a member of the DC-Network
        OutgoingMessage helloMessage(connectionID, HelloMessage, nodeID_);
        networkManager.sendMessage(helloMessage);
    }

    // start the message handler in a separate thread
    MessageHandler messageHandler(nodeID_, inbox, inboxDCNet, outbox);
    std::thread messageHandlerThread([&]() {
        messageHandler.run();
    });

    // start the write thread
    std::thread writerThread([&]() {
        for (;;) {
            auto message = outbox.pop();
            int result = networkManager.sendMessage(message);
            if (result < 0) {
                std::cout << "Error: could not send message" << std::endl;
            }
        }
    });

    // start the DCNetwork
    DCMember self(nodeID_, SELF, publicKey);
    DCNetwork DCNet(self, privateKey, INSTANCES, neighbors, inboxDCNet, outbox);

    // submit messages to the DCNetwork
    if (nodeID_ < 2) {
        uint16_t length = PRNG.GenerateWord32(512, 1024);
        std::vector<uint8_t> message(length);
        PRNG.GenerateBlock(message.data(), length);

        // for tests only
        // print the submitted message
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Message submitted by node " << nodeID_ << ":" << std::endl;
            for (uint8_t c : message) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
            }
            std::cout << std::endl << std::endl;
        }

        DCNet.submitMessage(message);
    }

    std::thread DCThread([&]() {
        DCNet.run();
    });


    DCThread.join();
    writerThread.join();
    messageHandlerThread.join();
    networkThread1.join();
}

void nodeAuthority() {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    typedef std::vector<uint8_t> NodeInfo;

    std::vector<NodeInfo> registeredNodes;

    MessageQueue<ReceivedMessage> inbox;

    io_context io_context_;
    uint16_t port = 7777;

    NetworkManager networkManager(io_context_, port, inbox);
    // Run the io_context which handles the network manager
    std::thread networkThread([&io_context_]() {
        io_context_.run();
    });

    // accept register messages until the threshold of nodes is reached
    for(uint32_t nodeID = 0; nodeID < INSTANCES; nodeID++) {
        auto receivedMessage = inbox.pop();
        if(receivedMessage.msgType() != RegisterMessage) {
            std::cout << "Unknown message type received: " << receivedMessage.msgType() << std::endl;
            continue;
        }
        // store the encoded information for each node
        registeredNodes.push_back(std::move(receivedMessage.body()));
        std::vector<uint8_t> encodedNodeID(4);
        encodedNodeID[0] = (nodeID & 0xFF000000) >> 24;
        encodedNodeID[1] = (nodeID & 0x00FF0000) >> 16;
        encodedNodeID[2] = (nodeID & 0x0000FF00) >> 8;
        encodedNodeID[3] = (nodeID & 0x000000FF);

        OutgoingMessage registerResponse(nodeID, RegisterResponse, 0, encodedNodeID);
        networkManager.sendMessage(registerResponse);
    }

    size_t infoSize = 10 + curve.GetCurve().EncodedPointSize(true);
    for(uint32_t i = 0; i < INSTANCES; i++) {
        std::vector<uint8_t> nodeInfo(4 + (INSTANCES-1) * infoSize);
        // the first 4 Bytes contain the number of instances
        nodeInfo[0] = ((INSTANCES-1) & 0xFF000000) >> 24;
        nodeInfo[1] = ((INSTANCES-1) & 0x00FF0000) >> 16;
        nodeInfo[2] = ((INSTANCES-1) & 0x0000FF00) >> 8;
        nodeInfo[3] = ((INSTANCES-1) & 0x000000FF);

        for(uint32_t nodeID = 0, offset = 4; nodeID < INSTANCES; nodeID++) {
            if(i != nodeID) {
                nodeInfo[offset]   = (nodeID & 0xFF000000) >> 24;
                nodeInfo[offset+1] = (nodeID & 0x00FF0000) >> 16;
                nodeInfo[offset+2] = (nodeID & 0x0000FF00) >> 8;
                nodeInfo[offset+3] = (nodeID & 0x000000FF);

                std::copy(registeredNodes[nodeID].begin(), registeredNodes[nodeID].end(), &nodeInfo[offset+4]);
                offset += infoSize;
            }
        }

        OutgoingMessage nodeInfoMessage(i, NodeInfoMessage, 0, nodeInfo);
        networkManager.sendMessage(nodeInfoMessage);
    }

    networkThread.join();
}

int main() {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    std::list<std::thread> threads;

    std::thread nodeAuthorityThread(nodeAuthority);
    threads.push_back(std::move(nodeAuthorityThread));

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    for(int i=0; i<INSTANCES; i++) {
        std::thread t(instance, i);
        threads.push_back(std::move(t));
    }

    for (auto it = threads.begin(); it != threads.end(); it++) {
        it->join();
    }
    return 0;
}
