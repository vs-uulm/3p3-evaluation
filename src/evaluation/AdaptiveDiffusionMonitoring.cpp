#include <cstdint>
#include <thread>
#include <list>
#include <iostream>
#include <fstream>
#include <cryptopp/oids.h>
#include <boost/tokenizer.hpp>

#include "../network/P2PConnection.h"
#include "../network/NetworkManager.h"
#include "../network/MessageHandler.h"
#include "../dc/DCNetwork.h"
#include "../datastruct/MessageType.h"
#include "../utils/Utils.h"
#include "../ad/VirtualSource.h"
#include "../network/UnsecuredNetworkManager.h"

std::mutex cout_mutex;
std::mutex logging_mutex;

const uint32_t INSTANCES = 100;

std::unordered_map<uint32_t, Node> nodes;

std::unordered_map<std::string, std::chrono::system_clock::time_point> startTimes;
std::unordered_map<std::string, std::vector<double>> sharedArrivalTimes;

std::vector<std::vector<uint32_t>> getTopology() {
    std::string file("/home/threePP/three-phase-protocol-implementation/sample_topologies/Graph_100Nodes_8Degree.csv");

    std::ifstream in(file.c_str());
    if (!in.is_open()) {
        std::cerr << "Error: could not open file" << std::endl;
        exit(1);
    }

    std::vector<std::vector<uint32_t>> graph;
    graph.reserve(INSTANCES);

    std::string line;
    for (uint32_t i = 0; i < INSTANCES; i++) {
        if (!getline(in, line))
            break;

        boost::tokenizer<boost::escaped_list_separator<char>> tokenizer(line);
        std::vector<uint32_t> neighbors;
        for (auto it = tokenizer.begin(); it != tokenizer.end(); it++) {
            if (it != tokenizer.begin())
                neighbors.push_back(std::atoi((*it).c_str()));
        }
        graph.push_back(neighbors);
    }
    return graph;
}

void instance(int ID) {
    CryptoPP::AutoSeededRandomPool PRNG;
    MessageQueue<ReceivedMessage> inboxThreePP;
    MessageQueue<ReceivedMessage> inboxDC;
    MessageQueue<OutgoingMessage> outboxThreePP;
    MessageQueue<std::vector<uint8_t>> outboxFinal;

    io_context io_context_;
    uint16_t port_ = 5555 + ID;
    uint32_t nodeID_ = ID;

    UnsecuredNetworkManager networkManager(io_context_, port_, inboxThreePP);
    // Run the io_context which handles the network manager
    std::thread networkThread([&io_context_]() {
        io_context_.run();
    });

    std::vector<std::vector<uint32_t>> topology = getTopology();
    // Add neighbors
    for (uint32_t nodeID : topology[nodeID_]) {
        if (nodeID > nodeID_) {
            std::lock_guard<std::mutex> lock(logging_mutex);
            uint32_t connectionID = networkManager.addNeighbor(nodes[nodeID]);
            if (connectionID < 0) {
                std::cout << "Error: could not add neighbour" << std::endl;
                continue;
            }
        }
    }

    // wait until all nodes are connected
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    std::vector<uint32_t> neighbors = networkManager.neighbors();

    // start the message handler in a separate thread
    MessageHandler messageHandler(nodeID_, neighbors, inboxThreePP, inboxDC, outboxThreePP, outboxFinal, 100, 128);
    std::thread messageHandlerThread([&]() {
        messageHandler.run();
    });

    // start the write thread
    std::thread writerThread([&]() {
        for (;;) {
            auto message = outboxThreePP.pop();
            if (message.msgType() != TerminateMessage) {
                if (networkManager.sendMessage(message) < 0) {
                    std::cout << "Error: could not send message" << std::endl;
                }
            } else {
                break;
            }
        }
    });

    std::this_thread::sleep_for(std::chrono::seconds(5));

    std::unordered_map<std::string, std::chrono::system_clock::time_point> arrivalTimes;
    // start the read thread
    std::thread readThread([&]() {
        for (;;) {
            std::vector<uint8_t> receivedMessage = outboxFinal.pop();
            if(receivedMessage.size() == 0)
                break;
            std::chrono::system_clock::time_point arrivalTime = std::chrono::system_clock::now();
            std::string msgHash = utils::sha256(receivedMessage);

            if(arrivalTimes.count(msgHash) == 0)
                arrivalTimes.insert(std::pair(msgHash, arrivalTime));
        }
    });

    uint32_t iterations = 50;
    if (nodeID_ == 0) {
        for (uint32_t i = 0; i < iterations; i++) {
            std::thread virtualSourceThread([&]() {
                // generate a random message
                std::vector<uint8_t> message(512);
                PRNG.GenerateBlock(message.data(), 512);
                std::string msgHash = utils::sha256(message);

                // prepare the arrivalTimeSlot
                std::vector<double> arrivalTimeVector(INSTANCES);
                {
                    std::lock_guard<std::mutex> lock(logging_mutex);
                    sharedArrivalTimes.insert(std::pair(msgHash, std::move(arrivalTimeVector)));
                }

                // check the current time
                std::chrono::system_clock::time_point startTime = std::chrono::system_clock::now();
                {
                    std::lock_guard<std::mutex> lock(logging_mutex);
                    startTimes.insert(std::pair(msgHash, startTime));
                }

                // trick the message handler
                outboxFinal.push(message);

                ReceivedMessage msg(0, AdaptiveDiffusionMessage, SELF, message);
                msg.timestamp(std::chrono::system_clock::now());
                inboxThreePP.push(std::move(msg));

                VirtualSource virtualSource(nodeID_, neighbors, outboxThreePP, inboxThreePP, message);
                virtualSource.executeTask();
            });
            virtualSourceThread.detach();
            std::cout << std::dec << i+1 << ". message submitted" << std::endl;
            if(i < iterations-1)
                std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    if(nodeID_ != 0)
        std::this_thread::sleep_for(std::chrono::seconds(5 * iterations));

    for (auto t : arrivalTimes) {
        std::lock_guard<std::mutex> lock(logging_mutex);
        std::chrono::duration<double> timeDifference = t.second - startTimes[t.first];
        sharedArrivalTimes[t.first][nodeID_] = timeDifference.count();
    }

    // clean up
    networkManager.terminate();
    io_context_.stop();
    networkThread.join();

    OutgoingMessage terminateWrite(SELF, TerminateMessage, SELF);
    outboxThreePP.push(terminateWrite);
    writerThread.join();

    ReceivedMessage terminateHandler(static_cast<uint8_t>(TerminateMessage));
    inboxThreePP.push(terminateHandler);
    messageHandlerThread.join();

    outboxFinal.push(std::vector<uint8_t>());
    readThread.join();
}

int main() {
    for(uint32_t i = 0; i < INSTANCES; i++) {
        Node node(i, 5555 + i, ip::address_v4::from_string("127.0.0.1"));
        std::lock_guard<std::mutex> lock(logging_mutex);
        nodes.insert(std::pair(i, node));
    }

    std::list<std::thread> threads;
    for (int i = 0; i < INSTANCES; i++) {
        std::thread t(instance, i);
        threads.push_back(std::move(t));
    }

    for (auto it = threads.begin(); it != threads.end(); it++) {
        it->join();
    }

    // log the runtimes
    // create the log file
    time_t now = time(0);
    tm* timeStamp = localtime(&now);
    std::string months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    std::stringstream fileName;
    fileName << "/home/threePP/evaluation/ADLog_";
    fileName << months[timeStamp->tm_mon];
    fileName << std::setw(2) << std::setfill('0') << timeStamp->tm_mday << "__";
    fileName << std::setw(2) << std::setfill('0') << timeStamp->tm_hour << "_";
    fileName << std::setw(2) << std::setfill('0') << timeStamp->tm_sec << "_";
    fileName << std::setw(2) << std::setfill('0') << timeStamp->tm_min << ".csv";

    std::ofstream logFile;
    logFile.open(fileName.str());

    for (uint32_t i = 0; i < INSTANCES; i++) {
        logFile << "Node " << i;
        if (i < INSTANCES - 1)
            logFile << ",";
        else
            logFile << std::endl;
    }

    for (auto &t : sharedArrivalTimes) {
        for (uint32_t i = 0; i < INSTANCES; i++) {
            logFile << t.second[i];
            if (i < INSTANCES - 1)
                logFile << ",";
            else
                logFile << std::endl;
        }
    }
    logFile.close();

    return 0;
}