#include <fstream>
#include <cryptopp/oids.h>
#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../dc/DCNetwork.h"
#include "../datastruct/MessageType.h"
#include "../network/UnsecuredNetworkManager.h"

int main(int argc, char** argv) {
    if(argc != 2)
        exit(1);

    uint32_t INSTANCES = atoi(argv[1]);

    // wait for cleaner logging
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    typedef std::vector<uint8_t> NodeInfo;

    std::unordered_map<uint32_t, std::pair<uint32_t, NodeInfo>> registeredNodes;

    MessageQueue<ReceivedMessage> inbox;

    io_context io_context_;
    uint16_t port = 7777;

    //NetworkManager networkManager(io_context_, port, inbox);
    UnsecuredNetworkManager networkManager(io_context_, port, inbox);

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

        OutgoingMessage nodeInfoMessage(node.second.first, NodeInfoMessage, 0, nodeInfo);
        networkManager.sendMessage(nodeInfoMessage);
    }

    // create the log file
    time_t now = time(0);
    tm* timeStamp = localtime(&now);
    std::string months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    std::stringstream fileName1;
    fileName1 << "/home/threePP/Log_";
    fileName1 << months[timeStamp->tm_mon];
    fileName1 << timeStamp->tm_mday << "__";
    fileName1 << timeStamp->tm_hour << "_";
    fileName1 << timeStamp->tm_min << "_";
    fileName1 << timeStamp->tm_sec << "_";
    fileName1 << "Round1" << ".csv";

    std::stringstream fileName2;
    fileName2 << "/home/threePP/Log_";
    fileName2 << months[timeStamp->tm_mon];
    fileName2 << timeStamp->tm_mday << "__";
    fileName2 << timeStamp->tm_hour << "_";
    fileName2 << timeStamp->tm_min << "_";
    fileName2 << timeStamp->tm_sec << "_";
    fileName2 << "Round2.csv";

    std::ofstream logFile1;
    logFile1.open (fileName1.str());

    logFile1 << "Security,Threads,";
    for(uint32_t i=0; i < INSTANCES; i++) {
        logFile1 << "Node" << i % INSTANCES << ",Preparation,SharingI,SharingII,Result,Total";
        if(i < INSTANCES-1)
            logFile1 << ",";
        else
            logFile1 << std::endl;
    }

    std::ofstream logFile2;
    logFile2.open (fileName2.str());

    logFile2 << "Security,Threads,";
    for(uint32_t i=0; i < INSTANCES; i++) {
        logFile2 << "Node" << i % INSTANCES << ",Preparation,SharingI,SharingII,Result,Total";
        if(i < INSTANCES-1)
            logFile2 << ",";
        else
            logFile2 << std::endl;
    }

    std::vector<std::pair<bool, std::vector<double>>> runtimes(INSTANCES);
    uint32_t iterations = 100;
    // collect log data
    for(uint32_t i = 0; i < 2 * iterations * INSTANCES; i++) {
        auto receivedMessage = inbox.pop();
        if(receivedMessage.msgType() != DCLoggingMessage) {
            std::cout << "Unknown message type received: " << receivedMessage.msgType() << std::endl;
            continue;
        }

        runtimes[receivedMessage.senderID()].first = receivedMessage.body()[34];
        std::vector<double> nodeRuntimes;
        nodeRuntimes.push_back(*reinterpret_cast<double *>(&receivedMessage.body()[0]));
        nodeRuntimes.push_back(*reinterpret_cast<double *>(&receivedMessage.body()[8]));
        nodeRuntimes.push_back(*reinterpret_cast<double *>(&receivedMessage.body()[16]));
        nodeRuntimes.push_back(*reinterpret_cast<double *>(&receivedMessage.body()[24]));
        runtimes[receivedMessage.senderID()].second = nodeRuntimes;

        if(((i+1) % (2*INSTANCES)) == 0) {
            // set the security level for Round2
            logFile2 << ((receivedMessage.body()[32] == 0) ? "unsecured" : "secured") << ",";
            // set the number of threads for Round2
            logFile2 << (int) receivedMessage.body()[35] << ",";
            // set runtimes and send flag
            for(uint32_t j = 0; j < INSTANCES; j++) {
                if(runtimes[j].first)
                    logFile2 << "sending,";
                else
                    logFile2 << ",";

                double total = 0;
                for(double runtime : runtimes[j].second) {
                    total += runtime;
                    logFile2 << runtime << ",";
                }
                logFile2 << total;
                if(j < INSTANCES-1)
                    logFile2 << ",";
                else
                    logFile2 << std::endl;
            }
        } else if((((i+1) % INSTANCES) == 0)) {
            // set the security level for Round1
            logFile1 << ((receivedMessage.body()[32] == 0) ? "unsecured" : "secured") << ",";
            // set the number of threads for Round1
            logFile1 << (int) receivedMessage.body()[35] << ",";
            // set runtimes and send flag
            for(uint32_t j = 0; j < INSTANCES; j++) {
                if(runtimes[j].first)
                    logFile1 << "sending,";
                else
                    logFile1 << ",";

                double total = 0;
                for(double runtime : runtimes[j].second) {
                    total += runtime;
                    logFile1 << runtime << ",";
                }
                logFile1 << total;
                if(j < INSTANCES-1)
                    logFile1 << ",";
                else
                    logFile1 << std::endl;
            }
        }
    }
    logFile1.close();
    logFile2.close();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    exit(0);

    networkThread.join();
    return 0;
}