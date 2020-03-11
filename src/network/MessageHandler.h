#ifndef THREEPP_MESSAGEHANDLER_H
#define THREEPP_MESSAGEHANDLER_H

#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/MessageQueue.h"
#include "../datastruct/ReceivedMessage.h"
#include "../datastruct/MessageBuffer.h"

class MessageHandler {
public:
    MessageHandler(uint32_t nodeID, MessageQueue<ReceivedMessage>& inbox, MessageQueue<ReceivedMessage>& inboxDCNet,
            MessageQueue<OutgoingMessage>& outbox);

    void run();

private:
    void handleHelloMsg(std::shared_ptr<ReceivedMessage> helloMsg);

    MessageQueue<ReceivedMessage>& inbox_;
    MessageQueue<ReceivedMessage>& inboxDCNet_;
    MessageQueue<OutgoingMessage>& outbox_;

    MessageBuffer msgBuffer;

    uint32_t nodeID_;
};


#endif //THREEPP_MESSAGEHANDLER_H
