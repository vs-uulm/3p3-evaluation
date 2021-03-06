
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <iomanip>

#include "../datastruct/ReceivedMessage.h"
#include "../network/P2PConnection.h"
#include "../network/SecuredNetworkManager.h"
#include "../network/MessageHandler.h"
#include "../dc/DCNetwork.h"
#include "../datastruct/MessageType.h"
#include "../network/NetworkManager.h"

ip::address getIP() {
    boost::asio::io_service io_service;
    tcp::socket socket(io_service);

    socket.connect(tcp::endpoint(ip::address_v4::from_string("8.8.8.8"), 443));
    ip::address ip_address = socket.local_endpoint().address();
    socket.close();

    return ip_address;
}

int main(int argc, char **argv) {
    if ((argc < 6) || (atoi(argv[1]) < 0) || (atoi(argv[1]) > 3)) {
        std::cout << "usage: ./dockerInstance securityLevel numThreads numSenders messageLength propagationDelay optimizationLevel" << std::endl;
        std::cout << "securityLevel" << std::endl;
        std::cout << "0: unsecured" << std::endl;
        std::cout << "1: secured" << std::endl;
        std::cout << "2: adaptive" << std::endl;
        std::cout << "optimizationLevel" << std::endl;
        std::cout << "0: full Protocol" << std::endl;
        std::cout << "1: no commitment validation" << std::endl;
        std::cout << "2: no commitment validation and prepared Commitments" << std::endl;
        exit(0);
    }

    SecurityLevel securityLevel = static_cast<SecurityLevel>(atoi(argv[1]));
    uint32_t numThreads = atoi(argv[2]);
    uint32_t numSenders = atoi(argv[3]);
    uint32_t messageLength = atoi(argv[4]);
    uint32_t propagationDelay = atoi(argv[5]);
    uint32_t optimizationLevel = 2;
    if(argc == 7)
        optimizationLevel = atoi(argv[6]);

    // wait for cleaner logging
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    CryptoPP::AutoSeededRandomPool PRNG;
    MessageQueue<ReceivedMessage> inboxThreePP;
    MessageQueue<ReceivedMessage> inboxDC;
    MessageQueue<OutgoingMessage> outboxThreePP;
    MessageQueue<std::vector<uint8_t>> outboxFinal;

    io_context io_context_;
    uint16_t port_ = 5555;
    ip::address ip_address = getIP();

    //NetworkManager networkManager(io_context_, port_, inboxThreePP);
    NetworkManager networkManager(io_context_, port_, inboxThreePP);
    // Run the io_context which handles the network manager
    std::thread networkThread1([&io_context_]() {
        io_context_.run();
    });

    // connect to the central node authority
    // wait a moment to ensure the central container is running
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    networkManager.connectToCA("172.28.1.1", 7777);

    // generate an EC keypair
    CryptoPP::Integer privateKey(PRNG, CryptoPP::Integer::One(), curve.GetMaxExponent());
    CryptoPP::ECPPoint publicKey = curve.ExponentiateBase(privateKey);

    std::vector<uint8_t> messageBody(6 + curve.GetCurve().EncodedPointSize(true));
    // set the port
    messageBody[0] = (port_ & 0xFF00) >> 8;
    messageBody[1] = (port_ & 0x00FF);

    std::array<uint8_t, 4> encodedIP = ip_address.to_v4().to_bytes();
    std::copy(&encodedIP[0], &encodedIP[5], &messageBody[2]);

    // set the compressed public key
    curve.GetCurve().EncodePoint(messageBody.data() + 6, publicKey, true);

    OutgoingMessage registerMessage(CENTRAL, Register, SELF, messageBody);
    networkManager.sendMessage(registerMessage);

    auto registerResponse = inboxThreePP.pop();
    if (registerResponse.msgType() != RegisterResponse)
        exit(1);

    // decode the received nodeID
    uint32_t nodeID_ = ((registerResponse.body()[0]) << 24) | (registerResponse.body()[1] << 16)
                       | (registerResponse.body()[2] << 8) | registerResponse.body()[3];

    // wait until the nodeInfo message arrives
    auto nodeInfo = inboxThreePP.pop();
    if (nodeInfo.msgType() != NodeInfo)
        exit(1);

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

    // wait until all nodes have received the information
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Add neighbors
    for (uint32_t i = 0; i < nodeID_; i++) {
        uint32_t connectionID = networkManager.addNeighbor(nodes[i]);
        if (connectionID < 0) {
            std::cout << "Error: could not add neighbour" << std::endl;
            continue;
        }
        // Add the node as a member of the DC-Network
        OutgoingMessage helloMessage(connectionID, DCConnect, nodeID_);
        networkManager.sendMessage(helloMessage);
    }

    std::vector<uint32_t> neighbors = networkManager.neighbors();

    // wait until all nodes have received the information
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // start the message handler in a separate thread
    MessageHandler messageHandler(nodeID_, neighbors, inboxThreePP, inboxDC, outboxThreePP, outboxFinal, propagationDelay);
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

    bool fullProtocol = true;
    bool preparedCommitments = false;
    if(optimizationLevel > 0)
        fullProtocol = false;
    if(optimizationLevel == 2)
        preparedCommitments = true;
    // start the DCNetwork
    DCMember self(nodeID_, SELF, publicKey);
    DCNetwork DCNetwork_(self, numNodes + 1, securityLevel, privateKey, numThreads, nodes, inboxDC, outboxThreePP, 0,
                         fullProtocol, true, preparedCommitments);

    std::thread DCThread([&]() {
        DCNetwork_.run();
    });

    uint32_t iterations = 100;
    // submit more messages to the DCNetwork
    for (uint32_t i = 0; i < iterations; i++) {
        if (nodeID_ < numSenders) {
            std::vector<uint8_t> message(messageLength);
            PRNG.GenerateBlock(message.data(), messageLength);
            DCNetwork_.submitMessage(message);
        }
    }

    // Terminate after all messages have been received
    while(outboxFinal.size() < numSenders * iterations) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
    networkManager.terminate();
    exit(0);


    DCThread.join();
    writerThread.join();
    messageHandlerThread.join();
    networkThread1.join();
}