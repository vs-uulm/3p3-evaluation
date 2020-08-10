#include <fstream>
#include <iomanip>
#include <cryptopp/oids.h>
#include "../network/P2PConnection.h"
#include "../network/SecuredNetworkManager.h"
#include "../dc/DCNetwork.h"
#include "../datastruct/MessageType.h"
#include "../network/NetworkManager.h"

int main(int argc, char** argv) {
    if(argc != 2)
        exit(1);

    uint32_t INSTANCES = atoi(argv[1]);
    uint32_t iterations = 100;
    // wait for cleaner logging
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    std::unordered_map<uint32_t, std::pair<uint32_t, std::vector<uint8_t>>> registeredNodes;

    MessageQueue<ReceivedMessage> inbox;

    io_context io_context_;
    uint16_t port = 7777;

    //NetworkManager networkManager(io_context_, port, inbox);
    NetworkManager networkManager(io_context_, port, inbox);

    // Run the io_context which handles the network manager
    std::thread networkThread([&io_context_]() {
        io_context_.run();
    });

    // accept register messages until the threshold of nodes is reached
    for(uint32_t nodeID = 0; nodeID < INSTANCES; nodeID++) {
        auto receivedMessage = inbox.pop();
        if(receivedMessage.msgType() != Register) {
            std::cout << "Unknown message type received: " << (int) receivedMessage.msgType() << std::endl;
            continue;
        }

        // store the encoded information for each node
        registeredNodes.insert(std::pair(nodeID, std::pair(receivedMessage.connectionID(), std::move(receivedMessage.body()))));
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
    for(auto& node : registeredNodes) {
        std::vector<uint8_t> nodeInfo(4 + (INSTANCES-1) * infoSize);
        // the first 4 Bytes contain the number of instances
        nodeInfo[0] = ((INSTANCES-1) & 0xFF000000) >> 24;
        nodeInfo[1] = ((INSTANCES-1) & 0x00FF0000) >> 16;
        nodeInfo[2] = ((INSTANCES-1) & 0x0000FF00) >> 8;
        nodeInfo[3] = ((INSTANCES-1) & 0x000000FF);

        for(uint32_t nodeID = 0, offset = 4; nodeID < INSTANCES; nodeID++) {
            if(node.first != nodeID) {
                nodeInfo[offset]   = (nodeID & 0xFF000000) >> 24;
                nodeInfo[offset+1] = (nodeID & 0x00FF0000) >> 16;
                nodeInfo[offset+2] = (nodeID & 0x0000FF00) >> 8;
                nodeInfo[offset+3] = (nodeID & 0x000000FF);

                std::copy(registeredNodes[nodeID].second.begin(), registeredNodes[nodeID].second.end(), &nodeInfo[offset+4]);
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

    fileName1 << "/home/threePP/Log_";
    fileName1 << months[timeStamp->tm_mon];
    fileName1 << timeStamp->tm_mday << "__";
    fileName1 << timeStamp->tm_hour << "_";
    fileName1 << timeStamp->tm_min << "_";
    fileName1 << timeStamp->tm_sec << "_";
    fileName1 << (secured ? "Secured_" : "Unsecured_");
    fileName1 << INSTANCES << "Nodes_";
    fileName1 << "Round1.csv";

    std::stringstream fileName2;
    fileName2 << "/home/threePP/Log_";
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
    std::this_thread::sleep_for(std::chrono::seconds(1));
    exit(0);

    networkThread.join();
    return 0;
}