#include <cryptopp/oids.h>
#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../dc/DCNetwork.h"
#include "../datastruct/MessageType.h"

int main(int argc, char** argv) {
    if(argc != 2)
        exit(1);

    uint32_t INSTANCES= atoi(argv[1]);

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    typedef std::vector<uint8_t> NodeInfo;

    std::vector<NodeInfo> registeredNodes;

    MessageQueue<ReceivedMessage> inbox;

    io_context io_context_;
    uint16_t port = 7777;

    //ensure oredered logging
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

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

        std::cout << "Central authority: node " << nodeID << " connected" << std::endl;
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
    return 0;
}