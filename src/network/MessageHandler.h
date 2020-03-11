#ifndef THREEPP_MESSAGEHANDLER_H
#define THREEPP_MESSAGEHANDLER_H

#include "../datastruct/NetworkMessage.h"
#include "../datastruct/MessageQueue.h"
#include "../datastruct/ReceivedMessage.h"
#include "../datastruct/MessageBuffer.h"

class MessageHandler {
public:
    MessageHandler(MessageQueue<ReceivedMessage>& inbox, MessageQueue<ReceivedMessage>& inboxDCNet,
            MessageQueue<NetworkMessage>& outbox);

    void run();

private:
    void handleHelloMsg(std::shared_ptr<ReceivedMessage> helloMsg);

    MessageQueue<ReceivedMessage>& inbox_;
    MessageQueue<ReceivedMessage>& inboxDCNet_;
    MessageQueue<NetworkMessage>& outbox_;

    MessageBuffer msgBuffer;
};


#endif //THREEPP_MESSAGEHANDLER_H
