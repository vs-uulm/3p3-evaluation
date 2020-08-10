#include <cstdint>
#include <thread>
#include <list>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cryptopp/oids.h>

#include "../network/P2PConnection.h"
#include "../network/SecuredNetworkManager.h"
#include "../network/MessageHandler.h"
#include "../dc/DCNetwork.h"
#include "../datastruct/MessageType.h"
#include "../utils/Utils.h"
#include "../network/NetworkManager.h"

const uint32_t iterations = 10;
const uint32_t INSTANCES = 6;
const uint32_t numSenders = 2;

void instance(int ID) {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    CryptoPP::AutoSeededRandomPool PRNG;
    MessageQueue<ReceivedMessage> inboxThreePP;
    MessageQueue<ReceivedMessage> inboxDC;
    MessageQueue<OutgoingMessage> outboxThreePP;
    MessageQueue<std::vector<uint8_t>> outboxFinal;

    io_context io_context_;
    uint16_t port_ = 5555 + ID;

    ip::address_v4 ip_address(ip::address_v4::from_string("127.0.0.1"));

    NetworkManager networkManager(io_context_, port_, inboxThreePP);
    // Run the io_context which handles the network manager
    std::thread networkThread([&io_context_]() {
        io_context_.run();
    });

    // connect to the central node authority
    networkManager.connectToCA("127.0.0.1", 7777);

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

    OutgoingMessage registerMessage(CENTRAL, Register, SELF, messageBody);
    networkManager.sendMessage(registerMessage);
    auto registerResponse = inboxThreePP.pop();

    while (registerResponse.msgType() != RegisterResponse) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        inboxThreePP.push(registerResponse);
        registerResponse = inboxThreePP.pop();
    }
    // decode the received nodeID
    uint32_t nodeID_ = ((registerResponse.body()[0]) << 24) | (registerResponse.body()[1] << 16)
                       | (registerResponse.body()[2] << 8) | registerResponse.body()[3];


    // wait until the nodeInfo message arrives
    auto nodeInfo = inboxThreePP.pop();
    while (nodeInfo.msgType() != NodeInfo) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        inboxThreePP.push(nodeInfo);
        nodeInfo = inboxThreePP.pop();
    }

    // First determine the number of nodes received
    uint32_t numNodes =
            (nodeInfo.body()[0] << 24) | (nodeInfo.body()[1] << 16) | (nodeInfo.body()[2] << 8) | (nodeInfo.body()[3]);

    std::unordered_map<uint32_t, Node> nodes;
    nodes.reserve(numNodes);

    // decode the submitted info
    size_t infoSize = 10 + curve.GetCurve().EncodedPointSize(true);
    for (uint32_t i = 0, offset = 4; i < numNodes; i++, offset += infoSize) {
        // extract the nodeID
        uint32_t nodeID = (nodeInfo.body()[offset] << 24) | (nodeInfo.body()[offset + 1] << 16)
                          | (nodeInfo.body()[offset + 2] << 8) | (nodeInfo.body()[offset + 3]);
        // extract the port
        uint16_t port = (nodeInfo.body()[offset + 4] << 8) | nodeInfo.body()[offset + 5];

        // extract the IP adddress
        std::array<uint8_t, 4> decodedIP;
        std::copy(&nodeInfo.body()[offset + 6], &nodeInfo.body()[offset + 10], &decodedIP[0]);
        ip::address_v4 ip_address(decodedIP);

        // decode the public key
        CryptoPP::ECPPoint publicKey;
        curve.GetCurve().DecodePoint(publicKey, &nodeInfo.body()[offset + 10], curve.GetCurve().EncodedPointSize(true));

        Node neighbor(nodeID, publicKey, port, ip_address);
        nodes.insert(std::pair(nodeID, neighbor));
    }

    // Add neighbors
    for (uint32_t i = 0; i < nodeID_; i++) {
        uint32_t connectionID = networkManager.addNeighbor(nodes[i]);
        if (connectionID < 0) {
            std::cout << "Error: could not add neighbour" << std::endl;
            exit(1);
        }

        // Add the node as a member of the DC-Network
        OutgoingMessage helloMessage(connectionID, DCConnect, nodeID_);
        networkManager.sendMessage(helloMessage);
    }

    // wait until all nodes are connected
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::vector<uint32_t> neighbors = networkManager.neighbors();

    // start the message handler in a separate thread
    MessageHandler messageHandler(nodeID_, neighbors, inboxThreePP, inboxDC, outboxThreePP, outboxFinal, 100);
    std::thread messageHandlerThread([&]() {
        messageHandler.run();
    });

    // start the write thread
    std::thread writerThread([&]() {
        for (;;) {
            OutgoingMessage message = outboxThreePP.pop();
            int result = networkManager.sendMessage(std::move(message));
            if (result < 0) {
                std::cout << "Error: could not send message" << std::endl;
            }
        }
    });

    // start the DCNetwork
    DCMember self(nodeID_, SELF, publicKey);
    DCNetwork DCNet(self, INSTANCES, Secured, privateKey, 2, nodes, inboxDC, outboxThreePP, 0, false, false);

    // submit messages to the DCNetwork
    for (uint32_t i = 0; i < iterations; i++) {
        if (nodeID_ < numSenders) {
            uint16_t length = PRNG.GenerateWord32(128, 512);
            std::vector<uint8_t> message(length);
            PRNG.GenerateBlock(message.data(), length);
            DCNet.submitMessage(message);
        }
    }

    // start the DCNetwork
    std::thread DCThread([&]() {
        DCNet.run();
    });

    // Terminate after all messages have been received
    while (outboxFinal.size() < numSenders * iterations) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));
    exit(0);

    DCThread.join();
    writerThread.join();
    messageHandlerThread.join();
    networkThread.join();
}

void nodeAuthority() {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    std::unordered_map<uint32_t, std::pair<uint32_t, std::vector<uint8_t>>> registeredNodes;

    MessageQueue<ReceivedMessage> inbox;

    io_context io_context_;
    uint16_t port = 7777;

    NetworkManager networkManager(io_context_, port, inbox);
    // Run the io_context which handles the network manager
    std::thread networkThread([&io_context_]() {
        io_context_.run();
    });

    // accept register messages until the threshold of nodes is reached
    for (uint32_t nodeID = 0; nodeID < INSTANCES; nodeID++) {
        auto receivedMessage = inbox.pop();
        // store the encoded information for each node
        registeredNodes.insert(
                std::pair(nodeID, std::pair(receivedMessage.connectionID(), receivedMessage.body())));
        std::vector<uint8_t> encodedNodeID(4);
        encodedNodeID[0] = (nodeID & 0xFF000000) >> 24;
        encodedNodeID[1] = (nodeID & 0x00FF0000) >> 16;
        encodedNodeID[2] = (nodeID & 0x0000FF00) >> 8;
        encodedNodeID[3] = (nodeID & 0x000000FF);

        OutgoingMessage registerResponse(receivedMessage.connectionID(), RegisterResponse, 0, encodedNodeID);
        networkManager.sendMessage(registerResponse);

        std::cout << "Central authority: node " << nodeID << " connected" << std::endl;
    }
    size_t infoSize = 10 + curve.GetCurve().EncodedPointSize(true);
    for (auto &node : registeredNodes) {
        std::vector<uint8_t> nodeInfo(4 + (INSTANCES - 1) * infoSize);
        // the first 4 Bytes contain the number of instances
        nodeInfo[0] = ((INSTANCES - 1) & 0xFF000000) >> 24;
        nodeInfo[1] = ((INSTANCES - 1) & 0x00FF0000) >> 16;
        nodeInfo[2] = ((INSTANCES - 1) & 0x0000FF00) >> 8;
        nodeInfo[3] = ((INSTANCES - 1) & 0x000000FF);

        for (uint32_t nodeID = 0, offset = 4; nodeID < INSTANCES; nodeID++) {
            if (node.first != nodeID) {
                nodeInfo[offset] = (nodeID & 0xFF000000) >> 24;
                nodeInfo[offset + 1] = (nodeID & 0x00FF0000) >> 16;
                nodeInfo[offset + 2] = (nodeID & 0x0000FF00) >> 8;
                nodeInfo[offset + 3] = (nodeID & 0x000000FF);

                std::copy(registeredNodes[nodeID].second.begin(), registeredNodes[nodeID].second.end(),
                          &nodeInfo[offset + 4]);
                offset += infoSize;
            }
        }

        OutgoingMessage nodeInfoMessage(node.second.first, NodeInfo, 0, nodeInfo);
        networkManager.sendMessage(nodeInfoMessage);
    }

    std::vector<std::vector<std::pair<bool, std::vector<double>>>> runtimesInitialRound(INSTANCES);
    for (auto &v : runtimesInitialRound)
        v.reserve(iterations);

    std::vector<std::vector<std::pair<bool, std::vector<double>>>> runtimesFinalRound(INSTANCES);
    for (auto &v : runtimesFinalRound)
        v.reserve(iterations);

    bool secured;
    uint32_t numThreads;
    // collect log data
    for (uint32_t i = 0; i < 2 * iterations * INSTANCES; i++) {
        auto receivedMessage = inbox.pop();
        if (receivedMessage.msgType() == DCNetworkLogging) {
            std::pair<bool, std::vector<double>> nodeLog;
            nodeLog.first = receivedMessage.body()[34];
            std::vector<double> nodeRuntimes;
            nodeRuntimes.push_back(*reinterpret_cast<double *>(&receivedMessage.body()[0]));
            nodeRuntimes.push_back(*reinterpret_cast<double *>(&receivedMessage.body()[8]));
            nodeRuntimes.push_back(*reinterpret_cast<double *>(&receivedMessage.body()[16]));
            nodeRuntimes.push_back(*reinterpret_cast<double *>(&receivedMessage.body()[24]));
            nodeLog.second = nodeRuntimes;
            if (receivedMessage.body()[33] == 1)
                runtimesInitialRound[receivedMessage.senderID()].push_back(nodeLog);
            else
                runtimesFinalRound[receivedMessage.senderID()].push_back(nodeLog);

            if (i == 0) {
                secured = receivedMessage.body()[32];
                numThreads = receivedMessage.body()[35];
            }
        }
    }
    std::cout << "Saving logs" << std::endl;

    // create the log files
    time_t now = time(0);
    tm *timeStamp = localtime(&now);
    std::string months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    std::stringstream fileName1;

    fileName1 << "/home/ubuntu/Log_";
    fileName1 << months[timeStamp->tm_mon];
    fileName1 << timeStamp->tm_mday << "__";
    fileName1 << timeStamp->tm_hour << "_";
    fileName1 << timeStamp->tm_min << "_";
    fileName1 << timeStamp->tm_sec << "_";
    fileName1 << (secured ? "Secured_" : "Unsecured_");
    fileName1 << INSTANCES << "Nodes_";
    fileName1 << "Round1.csv";

    std::stringstream fileName2;
    fileName2 << "/home/ubuntu/Log_";
    fileName2 << months[timeStamp->tm_mon];
    fileName2 << timeStamp->tm_mday << "__";
    fileName2 << timeStamp->tm_hour << "_";
    fileName2 << timeStamp->tm_min << "_";
    fileName2 << timeStamp->tm_sec << "_";
    fileName2 << (secured ? "Secured_" : "Unsecured_");
    fileName2 << INSTANCES << "Nodes_";
    fileName2 << "Round2.csv";

    std::ofstream logFile1;
    logFile1.open(fileName1.str());

    if (!logFile1.is_open()) {
        std::cerr << "Error: could not open file" << std::endl;
        exit(1);
    }

    logFile1 << "Security,Threads,";
    for (uint32_t i = 0; i < INSTANCES; i++) {
        logFile1 << "Node" << i % INSTANCES << ",Preparation,SharingI,SharingII,Result,Total";
        if (i < INSTANCES - 1)
            logFile1 << ",";
        else
            logFile1 << std::endl;
    }

    std::ofstream logFile2;
    logFile2.open(fileName2.str());

    logFile2 << "Security,Threads,";
    for (uint32_t i = 0; i < INSTANCES; i++) {
        logFile2 << "Node" << i % INSTANCES << ",Preparation,SharingI,SharingII,Result,Total";
        if (i < INSTANCES - 1)
            logFile2 << ",";
        else
            logFile2 << std::endl;
    }


    for (uint32_t i = 0; i < iterations; i++) {
        for (uint32_t n = 0; n < INSTANCES; n++) {
            // Final Round
            if(n == 0) {
                logFile2 << (secured ? "secured" : "unsecured") << ",";
                // set the number of threads for Round2
                logFile2 << numThreads << ",";
            }
            // set runtimes and send flag
            logFile2 << (runtimesFinalRound[n][i].first ? "sending," : ",");

            double total = 0;
            for (double runtime : runtimesFinalRound[n][i].second) {
                total += runtime;
                logFile2 << runtime << ",";
            }
            logFile2 << total << (n < INSTANCES-1 ? "," : "\n");

            // Initial Round
            if(n == 0) {
                logFile1 << (secured ? "secured" : "unsecured") << ",";
                // set the number of threads for Round1
                logFile1 << numThreads << ",";
            }
            // set runtimes and send flag
            logFile1 << (runtimesInitialRound[n][i].first ? "sending," : ",");

            total = 0;
            for (double runtime : runtimesInitialRound[n][i].second) {
                total += runtime;
                logFile1 << runtime << ",";
            }
            logFile1 << total << (n < INSTANCES-1 ? "," : "\n");
        }
    }
    logFile1.close();
    logFile2.close();

    networkThread.join();
}

int main() {
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    std::list<std::thread> threads;

    std::thread nodeAuthorityThread(nodeAuthority);
    threads.push_back(std::move(nodeAuthorityThread));

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    for (int i = 0; i < INSTANCES; i++) {
        std::thread t(instance, i);
        threads.push_back(std::move(t));
    }

    for (auto it = threads.begin(); it != threads.end(); it++) {
        it->join();
    }
    return 0;
}
