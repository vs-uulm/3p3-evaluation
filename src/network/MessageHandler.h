#ifndef THREEPP_MESSAGEHANDLER_H
#define THREEPP_MESSAGEHANDLER_H

#include <set>
#include <cryptopp/osrng.h>
#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/MessageQueue.h"
#include "../datastruct/ReceivedMessage.h"
#include "../datastruct/MessageBuffer.h"

class MessageHandler {
public:
    MessageHandler(uint32_t nodeID, std::vector<uint32_t>& neighbors,
            MessageQueue<ReceivedMessage>& inboxThreePP, MessageQueue<ReceivedMessage>& inboxDCNet,
            MessageQueue<OutgoingMessage>& outboxThreePP, MessageQueue<std::vector<uint8_t>>& outboxFinal,
            uint32_t propagationDelay = 100, uint32_t msgBufferSize = 128);

    void run();

private:
    MessageQueue<ReceivedMessage>& inboxThreePP_;

    MessageQueue<ReceivedMessage>& inboxDCNet_;

    MessageQueue<OutgoingMessage>& outboxThreePP_;

    MessageQueue<std::vector<uint8_t>>& outboxFinal_;

    MessageBuffer msgBuffer;

    uint32_t nodeID_;

    uint32_t propagationDelay_;

    std::vector<uint32_t>& neighbors_;

    CryptoPP::AutoSeededRandomPool PRNG;
};


#endif //THREEPP_MESSAGEHANDLER_H
