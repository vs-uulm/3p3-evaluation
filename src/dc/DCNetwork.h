#ifndef THREEPP_DCNETWORK_H
#define THREEPP_DCNETWORK_H

#include <map>
#include <cstdlib>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <unordered_map>
#include "../datastruct/MessageQueue.h"
#include "../datastruct/ReceivedMessage.h"
#include "DCState.h"
#include "../datastruct/OutgoingMessage.h"
#include "DCMember.h"
#include "../network/Node.h"

const CryptoPP::ECPPoint G(CryptoPP::Integer("362dc3caf8a0e8afd06f454a6da0cdce6e539bc3f15e79a15af8aa842d7e3ec2h"),
                CryptoPP::Integer("b9f8addb295b0fd4d7c49a686eac7b34a9a11ed2d6d243ad065282dc13bce575h"));

const CryptoPP::ECPPoint H(CryptoPP::Integer("a3cf0a4b6e1d9146c73e9a82e4bfdc37ee1587bc2bf3b0c19cb159ae362e38beh"),
                CryptoPP::Integer("db4369fabd3d770dd4c19d81ac69a1749963d69c687d7c4e12d186548b94cb2ah"));

enum SecurityLevel {
    Unsecured,
    Secured,
    Adaptive
};

class DCNetwork {
public:
    DCNetwork(DCMember self, CryptoPP::Integer privateKey, SecurityLevel securityLevel, size_t k,
            std::unordered_map<uint32_t, Node>& neighbors, MessageQueue<ReceivedMessage>& inbox, MessageQueue<OutgoingMessage>& outbox);

    std::map<uint32_t, DCMember>& members();

    std::unordered_map<uint32_t, Node>& neighbors();

    MessageQueue<ReceivedMessage>& inbox();

    MessageQueue<OutgoingMessage>& outbox();

    std::queue<std::vector<uint8_t>>& submittedMessages();

    uint32_t nodeID();

    size_t k();

    CryptoPP::Integer& privateKey();

    SecurityLevel securityLevel();

    void run();

    void submitMessage(std::vector<uint8_t>& msg);

private:
    uint32_t nodeID_;

    size_t k_;

    CryptoPP::Integer privateKey_;
    // Key: nodeID
    std::map<uint32_t, DCMember> members_;

    std::unordered_map<uint32_t, Node>& neighbors_;

    MessageQueue<ReceivedMessage>& inbox_;

    MessageQueue<OutgoingMessage>& outbox_;

    std::queue<std::vector<uint8_t>> submittedMessages_;

    // current state of the DC network
    std::unique_ptr<DCState> state_;

    // security setting of the DC Network
    SecurityLevel securityLevel_;
};


#endif //THREEPP_DCNETWORK_H
