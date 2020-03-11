#include <iostream>
#include "MessageHandler.h"
#include "../datastruct/MessageType.h"

std::mutex cout_mutex;

MessageHandler::MessageHandler(MessageQueue<ReceivedMessage> &inbox, MessageQueue<ReceivedMessage> &inboxDCNet,
        MessageQueue<NetworkMessage> &outbox)
        : inbox_(inbox), inboxDCNet_(inboxDCNet), outbox_(outbox), msgBuffer(0) {}


void MessageHandler::run() {
    for(;;) {
        auto receivedMessage = inbox_.pop();
        switch(receivedMessage->msgType()) {
            case HelloMsg:
                handleHelloMsg(receivedMessage);
                break;
            default:
                std::string body(receivedMessage->body().begin(), receivedMessage->body().end());
                {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "ConnectionID: " << receivedMessage->connectionID() << ", " << body << std::endl;
                }
        }
    }
}

void MessageHandler::handleHelloMsg(std::shared_ptr<ReceivedMessage> helloMsg) {
    uint32_t nodeID = *(helloMsg->body().data());
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Received hello message from Instance: " << nodeID
                  << " through connection: " << helloMsg->connectionID() << std::endl;
    }
}
